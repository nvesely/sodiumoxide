macro_rules! stream_module (($state_name: ident,
                             $init_push_name:ident,
                             $push_name:ident,
                             $init_pull_name:ident,
                             $pull_name:ident,
                             $rekey_name: ident,
                             $keybytes:expr,
                             $headerbytes:expr,
                             $abytes:expr,
                             $tag_message: expr,
                             $tag_push: expr,
                             $tag_rekey: expr,
                             $tag_final: expr) => (

#[cfg(not(feature = "std"))] use prelude::*;
use libc::c_ulonglong;
use num_traits::{FromPrimitive, ToPrimitive};
use randombytes::randombytes_into;
use std::mem;

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = $keybytes as usize;

/// An encrypted stream starts with a short header, whose size is `HEADERBYTES`
/// bytes. That header must be sent/stored before the sequence of encrypted
/// messages, as it is required to decrypt the stream.
pub const HEADERBYTES: usize = $headerbytes as usize;

/// The ciphertext length is guaranteed to always be message length plus `ABYTES`.
pub const ABYTES: usize = $abytes as usize;

/// A tag is attached to each message. A typical encrypted stream simply attaches
/// `Tag::Message` as a tag to all messages, except the last one which is tagged
/// as `Tag::Final`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Primitive)]
pub enum Tag {
    /// The most common tag, that doesn't add any information about the nature of
    /// the message.
    Message = $tag_message as u8,
    /// Indicates that the message marks the end of a set of messages, but not
    /// the end of the stream. For example, a huge JSON string sent as multiple
    /// chunks can use this tag to indicate to the application that the string is
    /// complete and that it can be decoded. But the stream itself is not closed,
    /// and more data may follow.
    Push = $tag_push as u8,
    /// "Forget" the key used to encrypt this message and the previous ones, and
    /// derive a new secret key.
    Rekey = $tag_rekey as u8,
    /// Indicates that the message marks the end of the stream, and erases the
    /// secret key used to encrypt the previous sequence.
    Final = $tag_final as u8,
}

new_type! {
    /// `Key` for symmetric encryption
    ///
    /// When a `Key` goes out of scope its contents
    /// will be zeroed out
    secret Key(KEYBYTES);
}

/// `gen_key()` randomly generates a key for symmetric encryption
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_key() -> Key {
    let mut key = [0; KEYBYTES];
    randombytes_into(&mut key);
    Key(key)
}

/// `State` contains the state for multi-part (streaming) computations. This allows the caller
/// to process a message as a sequence of multiple chunks.
pub struct State($state_name);

/// Initializes a `state` using the `key` and an internal, automatically generated initialization vector.
/// It then stores the stream header into header (crypto_secretstream_xchacha20poly1305_HEADERBYTES bytes).
pub fn init_push(key: &Key) -> (State, [u8; HEADERBYTES]) {
    unsafe {
        let mut state: $state_name = mem::uninitialized();
        let mut header: [u8; HEADERBYTES] = mem::uninitialized();
        $init_push_name(&mut state, header.as_mut_ptr(), key.0.as_ptr());
        (State(state), header)
    }
}

/// initializes a `state` given a secret `key` and a `header`.
/// The `key` k will not be required any more for subsequent operations.
/// It returns Err if the header is invalid.
pub fn init_pull(header: &[u8; HEADERBYTES], key: &Key) -> Result<State, ()> {
    unsafe {
        let mut state: $state_name = mem::uninitialized();
        if $init_pull_name(&mut state, header.as_ptr(), key.0.as_ptr()) != 0 {
            return Err(());
        }
        Ok(State(state))
    }
}

impl State {

    /// encrypts a message `m` using the `state` and the `tag`.
    /// Additional data ad of length adlen can be included in the computation of the authentication tag. If no additional data is required, ad can be None.
    pub fn push(&mut self, m: &[u8], ad: Option<&[u8]>, tag: Tag) -> Vec<u8> {
        let (ad_p, ad_len) = ad.map(|ad| (ad.as_ptr(), ad.len() as c_ulonglong)).unwrap_or((0 as *const _, 0));
        let mut c = Vec::with_capacity(m.len() + ABYTES);
        let mut clen = c.len() as c_ulonglong;
        
        unsafe {
            $push_name(&mut self.0,
                       c.as_mut_ptr(),
                       &mut clen,
                       m.as_ptr(),
                       m.len() as c_ulonglong,
                       ad_p,
                       ad_len,
                       tag.to_u8().unwrap());
            c.set_len(clen as usize);
        }
        c
    }
    
    /// Decrypt a ciphertext `c` after verifying it's authentication tag and
    /// optional associated data `ad`. If the ciphertext appears to be invalid, the
    /// function returns `Err(())`. If the authentication tag appears to be correct,
    /// the decrypted message is returned with tag. Applications will typically
    /// call this function in a loop, until a message with `Tag::Final` is found.
    pub fn pull(&mut self, c: &[u8], ad: Option<&[u8]>) -> Result<(Vec<u8>, Tag),()> {
        let (ad_p, ad_len) = ad.map(|ad| (ad.as_ptr(), ad.len() as c_ulonglong)).unwrap_or((0 as *const _, 0));
        let mut m = Vec::with_capacity(c.len() - ABYTES);
        let mut mlen = m.len() as c_ulonglong;
        let mut tag: u8 = unsafe { mem::uninitialized() };
        
        unsafe {
            if $pull_name(&mut self.0,
                          m.as_mut_ptr(),
                          &mut mlen,
                          &mut tag,
                          c.as_ptr(),
                          c.len() as c_ulonglong,
                          ad_p,
                          ad_len) != 0 {
                return Err(());
            }
            m.set_len(mlen as usize);
        }

        let tag = Tag::from_u8(tag);
        if tag.is_some() {
            Ok((m, tag.unwrap()))
        } else {
            Err(())
        }
    }
    
    /// Explicit rekeying, updates the state, but doesn't add any information about the key change to the stream.
    /// If this function is used to create an encrypted stream, the decryption process must call that function at the exact same stream location.
    pub fn rekey(&mut self) {
        unsafe {
            $rekey_name(&mut self.0);
        }
    }
}
));
