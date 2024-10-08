use pcsc::{Context, Error, Protocols, Scope, ShareMode};

fn main() -> Result<(), pcsc::Error> {
    let context = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Failed to establish context: {}", e);
            std::process::exit(1);
        }
    };

    let mut readers_buf = [0; 2048];
    let mut readers = match context.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(e) => {
            eprintln!("Failed to list readers: {}", e);
            std::process::exit(1);
        }
    };

    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            eprintln!("No readers are connected");
            std::process::exit(1);
        }
    };

    println!("Using reader {:?}", reader);

    let card = match context.connect(reader, ShareMode::Shared, Protocols::ANY) {
        Ok(card) => card,
        Err(Error::NoSmartcard) => {
            eprintln!("A smartcard is not present in the reader");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to connect to card: {}", e);
            std::process::exit(1);
        }
    };

    let read_card_identification_apdu = b"\x00\xB0\x00\x00\x41";

    // Select the tachograph application on the smart card
    transmit_select_df_apdu(&card, TACHOGRAPH_DF)?;
    // Select the identification file under the tachograph application
    transmit_select_ef_under_df_apdu(&card, TACHOGRAPH_IDENTIFICATION_EF)?;

    // Read the card identification file
    let read_card_identification_response = transmit_apdu(&card, read_card_identification_apdu)?;
    let (_, remaining) = take_n(1, &read_card_identification_response).unwrap();
    let (card_number, _) = take_n(16, remaining).unwrap();
    let driver_card_number = String::from_utf8(card_number.to_vec()).unwrap();
    println!("Driver card number: {}", driver_card_number);

    let read_card_holder_identification_apdu = b"\x00\xB0\x00\x41\x4E";
    let card_holder_identification_response = transmit_apdu(&card, read_card_holder_identification_apdu)?;
    let (card_holder_name, card_holder_remaining) = take_n(72, &card_holder_identification_response).unwrap();
    let (last_name, remaining) = take_n(36, &card_holder_name).unwrap();
    let (first_name, _) = take_n(36, &remaining).unwrap();
    let (birth_date, remaining) = take_n(4, card_holder_remaining).unwrap();
    let (preferred_language, _) = take_n(2, remaining).unwrap();
    let first_name = String::from_utf8(first_name.to_vec()).unwrap();
    let last_name = String::from_utf8(last_name.to_vec()).unwrap();
    let first_name = first_name.trim();
    let last_name = last_name.trim();
    let preferred_language = String::from_utf8(preferred_language.to_vec()).unwrap();
    println!("First name: {first_name}");
    println!("Last name: {last_name}");

    // Birth date is stored as BCDString where first two bytes denote the year and the last two bytes denote the month and day respectively
    let year = bcdstring_from_byte_string(&format!("{:08b}{:08b}", birth_date[0], birth_date[1]));
    let month = bcdstring_from_byte_string(&format!("{:08b}", birth_date[2]));
    let day = bcdstring_from_byte_string(&format!("{:08b}", birth_date[3]));
    println!("Year: {year}");
    println!("month: {month}");
    println!("day: {day}");
    println!("Preferred language: {}", preferred_language);

    Ok(())
}

fn transmit_select_df_apdu(card: &pcsc::Card, df: &[u8]) -> Result<Vec<u8>, Error> {
    let mut select_df_apdu = SELECT_DF_COMMAND.to_vec();
    select_df_apdu.extend_from_slice(df);
    transmit_apdu(card, &select_df_apdu)
}

fn transmit_select_ef_under_df_apdu(card: &pcsc::Card, ef: &[u8]) -> Result<Vec<u8>, Error> {
    let mut select_ef_apdu = SELECT_EF_UNDER_DF_COMMAND.to_vec();
    select_ef_apdu.extend_from_slice(ef);
    transmit_apdu(card, &select_ef_apdu)
}

fn transmit_read_binary_apdu(card: &pcsc::Card, offset: u8, length: u8) -> Result<Vec<u8>, Error> {
    let mut read_binary_apdu = READ_BINARY_COMMAND.to_vec();
    read_binary_apdu.push(offset);
    read_binary_apdu.push(length);
    transmit_apdu(card, &read_binary_apdu)
}

const SELECT_DF_COMMAND: &[u8] = b"\x00\xA4\x04\x0C\x06";
const SELECT_EF_UNDER_DF_COMMAND: &[u8] = b"\x00\xA4\x02\x0C\x02";
const READ_BINARY_COMMAND: &[u8] = b"\x00\xB0";

const TACHOGRAPH_DF: &[u8] = b"\xFF\x54\x41\x43\x48\x4F";
const TACHOGRAPH_GEN2_DF: &[u8] = b"\xFF\x53\x4D\x52\x44\x54";

const TACHOGRAPH_IDENTIFICATION_EF: &[u8] = b"\x05\x20";

const CARD_IDENTIFICATION_LENGTH: &[u8] = b"\x41";
const DRIVER_CARD_HOLDER_IDENTIFICATION_LENGTH: &[u8] = b"\x4E";


/// Converts a byte string to a BCD string
///
/// VERY EXPERIMENTAL, see [Binacy-Coded Decimal](https://en.wikipedia.org/wiki/Binary-coded_decimal)
///
/// # Arguments
/// - `data` - A string of bytes
fn bcdstring_from_byte_string(data: &str) -> String {
    data.chars()
    .collect::<Vec<char>>()
    .chunks(4)
    .map(|chunk|
        u8::from_str_radix(&chunk.iter().collect::<String>(), 2)
        .unwrap()
        .to_string())
    .collect::<Vec<String>>()
    .join("")
}

/// Takes the first `n` bytes from a byte slice
///
/// # Arguments
/// - `n` - The number of bytes to take
/// - `data` - The byte slice to take the bytes from
///
/// # Returns
/// A tuple containing the first `n` bytes and the remaining bytes
fn take_n(n: usize, data: &[u8]) -> Result<(&[u8], &[u8]), std::io::Error> {
    if data.len() < n {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Data is too short",
        ));
    }
    Ok(data.split_at(n))
}

/// Transmits an APDU to a smart card
///
/// # Arguments
/// - `card` - The smart card to transmit the APDU to
/// - `apdu` - The APDU to transmit
///
/// # Returns
/// The response from the smart card
fn transmit_apdu(card: &pcsc::Card, apdu: &[u8]) -> Result<Vec<u8>, Error> {
    let mut rapdu_buf = [0; 1024];
    match card.transmit(apdu, &mut rapdu_buf) {
        Ok(response) => Ok(response.to_vec()),
        Err(e) => {
            eprintln!("Failed to transmit APDU: {}", e);
            Err(e)
        }
    }
}
