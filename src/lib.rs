#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(target_endian = "little"))]
core::compile_error!("This crate is only supported on little-endian systems.");

use core::mem::size_of;

#[cfg(feature = "std")]
use std::time::Duration;

/// The epoch used by cFS APIs in the flight software,
/// in terms of offset relative to the Unix epoch.
#[cfg(feature = "std")]
const FLIGHT_SOFTWARE_EPOCH: Duration = Duration::new(315532800, 0); // 1980-01-01T00:00:00 UTC

/// A cFS-flavor CCSDS command packet, as a Rust structure.
#[repr(C)]
#[derive(Clone)]
pub struct Command<T: Copy> {
    /// The command header.
    header: [u8; 8],

    /// The message's payload. As messages are copied
    /// willy-nilly, `T` needs to be [`Copy`].
    pub payload: T,
}

/// A cFS-flavor CCSDS telemetry packet, as a Rust structure.
#[repr(C)]
#[derive(Clone)]
pub struct Telemetry<T: Copy> {
    /// The telemetry header.
    header: [u8; 16],

    /// The message's payload. As messages are copied
    /// willy-nilly, `T` needs to be [`Copy`].
    pub payload: T,
}

impl<T: Copy> Command<T> {
    const ALLOWED_MSG_ID_RANGE: core::ops::RangeInclusive<u32> = 0x1800..=0x1FFF;
    const MAX_FUNCTION_CODE: u16 = 0x7F;

    /// If `msg_id` and `function_code` are a permissible message ID and a permissible command code (respectively),
    /// returns a new `Command` with the payload initialized to `payload`; otherwise returns an error.
    pub fn new(msg_id: u32, function_code: u16, payload: T) -> Result<Self, ()> {
        let len_field = size_of::<Self>().checked_sub(7).unwrap();

        // check that fields are in their allowed ranges
        if Self::ALLOWED_MSG_ID_RANGE.contains(&msg_id)
            && function_code <= Self::MAX_FUNCTION_CODE
            && len_field <= 0xFFFF
        {
            #[rustfmt::skip]
            let header = [
                //                                             CCSDS primary header:
                (msg_id >> 8) as u8, msg_id as u8,          // packet version number and packet identification
                0xC0, 0x00,                                 // packet sequence control
                (len_field >> 8) as u8, len_field as u8,    // packet data length
                //                                             cFS secondary header for commands:
                function_code as u8, 0x00,                  // command code and optional checksum
            ];
            Ok(Self { header, payload })
        } else {
            Err(())
        }
    }

    /// [`Self::new`], but using [`Default::default`]`()` as the payload.
    pub fn new_default(msg_id: u32, function_code: u16) -> Result<Self, ()>
    where
        T: Default,
    {
        Self::new(msg_id, function_code, Default::default())
    }

    /// Returns a view of the `Command` as a sequence of bytes, ready for transmission.
    pub fn as_bytes(&self) -> &[u8] {
        // Safety: all fields of Command<T> are Copy (so no *Cell fields),
        // and we're using the lifetime of an immutable ref to self.
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Turns a sequence of bytes representing a message into a `Command`,
    /// assuming `bytes` is the correct length and the header bytes have sane values.
    ///
    /// # Safety
    ///
    /// Using this function is only safe if the part of `bytes`
    /// at bytes `8..(8 + std::mem::size_of::<T>())`
    /// is byte-for-byte equal to a valid item of type `T`.
    pub unsafe fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        // first off, do sanity checking of message length
        // and the fields we know how to sanity-check:
        if bytes.len() != size_of::<Self>() {
            return Err(());
        }

        let msg_id = ((bytes[0] as u32) << 8) | (bytes[1] as u32);
        let msg_len = (((bytes[4] as usize) << 8) | (bytes[5] as usize))
            .checked_add(7)
            .unwrap();

        if !(Self::ALLOWED_MSG_ID_RANGE.contains(&msg_id))
            || (msg_len != size_of::<Self>())
            || (bytes[2] & 0xC0 != 0xC0)
            || (bytes[6] & 0x80 != 0x00)
        {
            return Err(());
        }

        // here comes the unsafe part:
        let mut cmd = core::mem::MaybeUninit::<Self>::uninit();
        cmd.as_mut_ptr()
            .write(core::ptr::read_unaligned(bytes.as_ptr() as *const Self));
        Ok(cmd.assume_init())
    }

    /// Returns the message's message ID.
    pub fn msg_id(&self) -> u32 {
        ((self.header[0] as u32) >> 8) | (self.header[1] as u32)
    }

    /// Returns the message's command code.
    pub fn function_code(&self) -> u16 {
        self.header[6] as u16
    }

    /// If `msg_id` is a valid message ID, sets the message's message ID to `msg_id`.
    pub fn set_msg_id(&mut self, msg_id: u32) -> Result<(), ()> {
        if Self::ALLOWED_MSG_ID_RANGE.contains(&msg_id) {
            self.header[0] = (msg_id >> 8) as u8;
            self.header[1] = msg_id as u8;
            Ok(())
        } else {
            Err(())
        }
    }

    /// If `function_code` is a valid command code, sets the message's function code to `function_code`.
    pub fn set_function_code(&mut self, function_code: u16) -> Result<(), ()> {
        if function_code <= Self::MAX_FUNCTION_CODE {
            self.header[6] = function_code as u8;
            Ok(())
        } else {
            Err(())
        }
    }
}

impl<T: Copy> Telemetry<T> {
    const ALLOWED_MSG_ID_RANGE: core::ops::RangeInclusive<u32> = 0x0800..=0x0FFF;

    /// If `msg_id` is a permissible message ID,
    /// returns a new `Telemetry` with the payload initialized to `payload`; otherwise returns an error.
    pub fn new(msg_id: u32, payload: T) -> Result<Self, ()> {
        let len_field = size_of::<Self>().checked_sub(7).unwrap();

        // check that fields are in their allowed ranges
        if Self::ALLOWED_MSG_ID_RANGE.contains(&msg_id) && len_field <= 0xFFFF {
            #[rustfmt::skip]
            let header = [
                //                                             CCSDS primary header:
                (msg_id >> 8) as u8, msg_id as u8,          // packet version number and packet identification
                0xC0, 0x00,                                 // packet sequence control
                (len_field >> 8) as u8, len_field as u8,    // packet data length
                //                                             cFS secondary header for telemetry, default contents:
                0, 0, 0, 0,                                 // timestamp (seconds part)
                0, 0,                                       // timestamp (subseconds part)
                0, 0, 0, 0,                                 // structure padding
            ];
            Ok(Self { header, payload })
        } else {
            Err(())
        }
    }

    /// [`Self::new`], but using [`Default::default`]`()` as the payload.
    pub fn new_default(msg_id: u32) -> Result<Self, ()>
    where
        T: Default,
    {
        Self::new(msg_id, Default::default())
    }

    /// Returns a view of the `Telemetry` as a sequence of bytes, ready for transmission.
    pub fn as_bytes(&self) -> &[u8] {
        // Safety: all fields of Telemetry<T> are Copy (so no *Cell fields),
        // and we're using the lifetime of an immutable ref to self.
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Turns a sequence of bytes representing a message into a `Telemetry`,
    /// assuming `bytes` is the correct length and the header bytes have sane values.
    ///
    /// # Safety
    ///
    /// Using this function is only safe if the part of `bytes`
    /// at bytes `16..(16 + std::mem::size_of::<T>())`
    /// is byte-for-byte equal to a valid item of type `T`.
    pub unsafe fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        // first off, do sanity checking of message length
        // and the fields we know how to sanity-check:
        if bytes.len() != size_of::<Self>() {
            return Err(());
        }

        let msg_id = ((bytes[0] as u32) << 8) | (bytes[1] as u32);
        let msg_len = (((bytes[4] as usize) << 8) | (bytes[5] as usize))
            .checked_add(7)
            .unwrap();

        if !(Self::ALLOWED_MSG_ID_RANGE.contains(&msg_id))
            || (msg_len != size_of::<Self>())
            || (bytes[2] & 0xC0 != 0xC0)
        {
            return Err(());
        }

        // here comes the unsafe part:
        let mut tlm = core::mem::MaybeUninit::<Self>::uninit();
        tlm.as_mut_ptr()
            .write(core::ptr::read_unaligned(bytes.as_ptr() as *const Self));
        Ok(tlm.assume_init())
    }

    /// Returns the message's message ID.
    pub fn msg_id(&self) -> u32 {
        ((self.header[0] as u32) >> 8) | (self.header[1] as u32)
    }

    /// Returns the message's timestamp as a tuple of
    /// (seconds since flight-software epoch, subseconds in units of 2<sup>&minus;16</sup> s).
    pub fn timestamp(&self) -> (u32, u16) {
        let seconds = ((self.header[6] as u32) << 24)
            | ((self.header[7] as u32) << 16)
            | ((self.header[8] as u32) << 8)
            | (self.header[9] as u32);
        let subsecs = ((self.header[10] as u16) << 8) | (self.header[11] as u16);

        (seconds, subsecs)
    }

    /// Returns the message's sequence number.
    pub fn sequence_number(&self) -> u16 {
        let sequence_header = ((self.header[2] as u16) << 8) | (self.header[3] as u16);

        sequence_header & 0x3FFF
    }

    /// If `msg_id` is a valid message ID, uses it to set the message's message ID.
    pub fn set_msg_id(&mut self, msg_id: u32) -> Result<(), ()> {
        if Self::ALLOWED_MSG_ID_RANGE.contains(&msg_id) {
            self.header[0] = (msg_id >> 8) as u8;
            self.header[1] = msg_id as u8;
            Ok(())
        } else {
            Err(())
        }
    }

    /// Sets the message's timestamp to
    /// `seconds` seconds + `nanoseconds` nanoseconds
    /// since the flight-software epoch, rounded to 2<sup>&minus;16</sup> seconds.
    pub fn set_timestamp(&mut self, seconds: u64, nanoseconds: u32) {
        // the 4-byte seconds field is seconds since epoch,
        // the 2-byte subseconds field is fractional part of time (in units of 2^-16 second)

        // subseconds, in units of 2^-16 sec
        let subsecs = (nanoseconds as u64 * (1 << 16)) / 1_000_000_000;

        self.header[6] = (seconds >> 24) as u8;
        self.header[7] = (seconds >> 16) as u8;
        self.header[8] = (seconds >> 8) as u8;
        self.header[9] = seconds as u8;
        self.header[10] = (subsecs >> 8) as u8;
        self.header[11] = subsecs as u8;
    }

    /// Sets the message's timestamp to the current time.
    #[cfg(feature = "std")]
    pub fn timestamp_with_now(&mut self) -> Result<(), std::time::SystemTimeError> {
        use std::time::SystemTime;

        let epoch_time =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH + FLIGHT_SOFTWARE_EPOCH)?;

        self.set_timestamp(epoch_time.as_secs(), epoch_time.subsec_nanos());
        Ok(())
    }

    /// Increment the message's sequence number.
    pub fn increment_sequence_num(&mut self) {
        let sequence_header = ((self.header[2] as u16) << 8) | (self.header[3] as u16);

        let new_sequence_header = (sequence_header.wrapping_add(1) & 0x3FFF) | 0xC000;

        self.header[2] = (new_sequence_header >> 8) as u8;
        self.header[3] = new_sequence_header as u8;
    }
}

/// Takes a `str` or `String` and uses it to populate an array of `c_char`s.
///
/// If `ensure_null_termination` is set, the last byte of the array is guaranteed to be `'\0'`.
///
/// Returns the array, as well as whether any bytes were truncated at the end of `string`.
pub fn fill_char_array<S: AsRef<[u8]>, const N: usize>(
    string: &S,
    ensure_null_termination: bool,
) -> ([core::ffi::c_char; N], bool) {
    use core::ffi::c_char;
    let mut output = [0 as c_char; N];

    let bytes = string.as_ref();

    let max_untruncated_len = if ensure_null_termination { N - 1 } else { N };
    let is_truncated = (bytes.len() > max_untruncated_len)
        || (bytes.len() == max_untruncated_len && !(bytes.iter().any(|b| b'\0' == *b)));

    for (i, in_byte) in bytes.iter().take(max_untruncated_len).enumerate() {
        output[i] = (*in_byte) as c_char;
    }

    (output, is_truncated)
}
