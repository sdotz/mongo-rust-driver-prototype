//! Authentication schemes.
use bson::Bson::{self, Binary};
use bson::Document;
use bson::spec::BinarySubtype::Generic;
use CommandType::Suppressed;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::md5::Md5;
use crypto::pbkdf2;
use crypto::sha1::Sha1;
use db::{Database, ThreadedDatabase};
use error::Error::{DefaultError, MaliciousServerError, ResponseError};
use error::MaliciousServerErrorType;
use error::Result;
use rustc_serialize::base64::{self, FromBase64, ToBase64};
use rustc_serialize::hex::{ToHex};
use textnonce::TextNonce;

const B64_CONFIG : base64::Config = base64::Config { char_set: base64::CharacterSet::Standard,
                                                     newline: base64::Newline::LF,
                                                     pad: true, line_length: None };

/// Handles SCRAM-SHA-1 authentication logic.
pub struct Authenticator {
    db: Database,
}

#[derive(Debug)]
struct NonceData {
    nonce: String,
}

#[derive(Debug)]
struct KeyData {
    key: String,
}

struct InitialData {
    message: String,
    response: String,
    nonce: String,
    conversation_id: Bson,
}

struct AuthData {
    salted_password: Vec<u8>,
    message: String,
    response: Document,
}

impl Authenticator {
    /// Creates a new authenticator.
    pub fn new(db: Database) -> Authenticator {
        Authenticator { db: db }
    }

    /// Authenticates a user-password pair against a database.
    pub fn auth(self, user: &str, password: &str) -> Result<()> {
        let initial_data = try!(self.start(user));
        let conversation_id = initial_data.conversation_id.clone();
        let full_password = format!("{}:mongo:{}", user, password);
        let auth_data = try!(self.next(full_password, initial_data));

        self.finish(conversation_id, auth_data)
    }

    pub fn auth_cr(self, user: &str, password: &str) -> Result<()> {
        let nonce = try!(self.get_nonce());
        let key = try!(self.compute_key(user, password, &nonce.nonce));
        try!(self.send_auth_cr(user, &nonce.nonce, &key.key));
        Ok(())
    }

    fn send_auth_cr(&self, user: &str, nonce: &str, key: &str) -> Result<()> {
        let auth_cr_doc = doc! {
            "authenticate" => 1,
            "user" => user,
            "nonce" => nonce,
            "key" => key
        };

        let result = try!(self.db.command(auth_cr_doc, Suppressed, None));

        let result = result.get("ok");

        println!("Auth Result: {:?}", result);

        match result {
            Some(&Bson::I32(1)) => Ok(()),
            _ => Err(ResponseError("Auth Failed, got non-1".to_owned()))
        }
    }

    fn compute_key(&self, user: &str, password: &str, nonce: &str) -> Result<KeyData> {
        let pass_str = format!("{}:mongo:{}", user, password);
        let mut md5 = Md5::new();
        md5.input_str(&pass_str[..]);
        let mut output_ha1 = [0; 16];
        md5.result(&mut output_ha1);
        let password_digest = &output_ha1.to_hex();

        let combine = format!("{}{}{}", nonce, user, password_digest);
        let mut md5 = Md5::new();
        md5.input_str(&combine[..]);
        let mut output_ha2 = [0; 16];
        md5.result(&mut output_ha2);
        let combine_digest = &output_ha2.to_hex();

        Ok(KeyData{key: combine_digest.to_string()})
    }

    fn get_nonce(&self) -> Result<NonceData> {
        let get_nonce_doc = doc! {
            "getnonce" => 1
        };

        let result = try!(self.db.command(get_nonce_doc, Suppressed, None));

        let nonce = result.get("nonce");

        match nonce {
            Some(&Bson::String(ref nonce)) => Ok(NonceData{nonce: nonce.to_string()}),
            _ => Err(ResponseError("Get nonce command failed".to_owned()))
        }
    }

    fn start(&self, user: &str) -> Result<InitialData> {
        let text_nonce = match TextNonce::sized(64) {
            Ok(text_nonce) => text_nonce,
            Err(string) => return Err(DefaultError(string))
        };

        let nonce = format!("{}", text_nonce);
        let message = format!("n={},r={}", user, nonce);
        let bytes = format!("n,,{}", message).into_bytes();
        let binary = Binary(Generic, bytes);

        let start_doc = doc! {
            "saslStart" => 1,
            "autoAuthorize" => 1,
            "payload" => binary,
            "mechanism" => "SCRAM-SHA-1"
        };

        let doc = try!(self.db.command(start_doc, Suppressed, None));
        let data = match doc.get("payload") {
            Some(&Binary(_, ref payload)) => payload.to_owned(),
            _ => return Err(ResponseError("Invalid payload returned".to_owned()))
        };

        let id = match doc.get("conversationId") {
            Some(bson) => bson.clone(),
            None => return Err(ResponseError("No conversationId returned".to_owned()))
        };

        let response = match String::from_utf8(data) {
            Ok(string) => string,
            Err(_) => return Err(ResponseError("Invalid UTF-8 payload returned".to_owned()))
        };

        Ok(InitialData { message: message, response: response, nonce: nonce,
                          conversation_id: id })
    }

    fn next(&self, password: String, initial_data: InitialData) -> Result<AuthData> {
        // Parse out rnonce, salt, and iteration count
        let (rnonce_opt, salt_opt, i_opt) = scan_fmt!(&initial_data.response[..], "r={},s={},i={}", String, String, u32);

        let rnonce_b64 = match rnonce_opt {
            Some(val) => val,
            None => return Err(ResponseError("Invalid rnonce returned".to_owned()))
        };

        // Validate rnonce to make sure server isn't malicious
        if !rnonce_b64.starts_with(&initial_data.nonce[..]) {
            return Err(MaliciousServerError(MaliciousServerErrorType::InvalidRnonce))
        }

        let salt_b64 = match salt_opt {
            Some(val) => val,
            None => return Err(ResponseError("Invalid salt returned".to_owned()))
        };

        let salt = match salt_b64.from_base64() {
            Ok(val) => val,
            Err(_) => return Err(ResponseError("Invalid base64 salt returned".to_owned()))
        };


        let i = match i_opt {
            Some(val) => val,
            None => return Err(ResponseError("Invalid iteration count returned".to_owned()))
        };

        // Hash password
        let mut md5 = Md5::new();
        md5.input_str(&password[..]);
        let hashed_password = md5.result_str();

        // Salt password
        let mut hmac = Hmac::new(Sha1::new(), hashed_password.as_bytes());
        let mut salted_password : Vec<_> = (0..hmac.output_bytes()).map(|_| 0).collect();
        pbkdf2::pbkdf2(&mut hmac, &salt[..], i, &mut salted_password);

        // Compute client key
        let mut client_key_hmac = Hmac::new(Sha1::new(), &salted_password[..]);
        let client_key_bytes = "Client Key".as_bytes();
        client_key_hmac.input(client_key_bytes);
        let client_key = client_key_hmac.result().code().to_owned();

        // Hash into stored key
        let mut stored_key_sha1 = Sha1::new();
        stored_key_sha1.input(&client_key[..]);
        let mut stored_key : Vec<_> = (0..stored_key_sha1.output_bytes()).map(|_| 0).collect();
        stored_key_sha1.result(&mut stored_key);

        // Create auth message
        let without_proof = format!("c=biws,r={}", rnonce_b64);
        let auth_message = format!("{},{},{}", initial_data.message, initial_data.response, without_proof);

        // Compute client signature
        let mut client_signature_hmac = Hmac::new(Sha1::new(), &stored_key[..]);
        client_signature_hmac.input(auth_message.as_bytes());
        let client_signature = client_signature_hmac.result().code().to_owned();

        // Sanity check
        if client_key.len() != client_signature.len() {
            return Err(DefaultError("Generated client key and/or client signature is invalid".to_owned()));
        }

        // Compute proof by xor'ing key and signature
        let mut proof = vec![];
        for i in 0..client_key.len() {
            proof.push(client_key[i] ^ client_signature[i]);
        }

        // Encode proof and produce the message to send to the server
        let b64_proof = proof.to_base64(B64_CONFIG);
        let final_message = format!("{},p={}", without_proof, b64_proof);
        let binary = Binary(Generic, final_message.into_bytes());

        let next_doc = doc! {
            "saslContinue" => 1,
            "payload" => binary,
            "conversationId" => (initial_data.conversation_id.clone())
        };

        let response = try!(self.db.command(next_doc, Suppressed, None));

        Ok(AuthData { salted_password: salted_password, message: auth_message,
                      response: response })
    }

    fn finish(&self, conversation_id: Bson, auth_data: AuthData) -> Result<()> {
        let final_doc = doc! {
            "saslContinue" => 1,
            "payload" => (Binary(Generic, vec![])),
            "conversationId" => conversation_id
        };

        // Compute server key
        let mut server_key_hmac = Hmac::new(Sha1::new(), &auth_data.salted_password[..]);
        let server_key_bytes = "Server Key".as_bytes();
        server_key_hmac.input(server_key_bytes);
        let server_key = server_key_hmac.result().code().to_owned();

        // Compute server signature
        let mut server_signature_hmac = Hmac::new(Sha1::new(), &server_key[..]);
        server_signature_hmac.input(auth_data.message.as_bytes());
        let server_signature = server_signature_hmac.result().code().to_owned();

        let mut doc = auth_data.response;

        loop {
            // Verify server signature
            if let Some(&Binary(_, ref payload)) = doc.get("payload") {
                let payload_str = match String::from_utf8(payload.to_owned()) {
                    Ok(string) => string,
                    Err(_) => return Err(ResponseError("Invalid UTF-8 payload returned".to_owned()))
                };

                // Check that the signature exists
                let verifier = match scan_fmt!(&payload_str[..], "v={}", String) {
                    Some(string) => string,
                    None => return Err(MaliciousServerError(MaliciousServerErrorType::NoServerSignature)),
                };

                // Check that the signature is valid
                if verifier.ne(&server_signature.to_base64(B64_CONFIG)[..]) {
                    return Err(MaliciousServerError(MaliciousServerErrorType::InvalidServerSignature));
                }
            }

            doc = try!(self.db.command(final_doc.clone(), Suppressed, None));

            if let Some(&Bson::Boolean(true)) = doc.get("done") {
                return Ok(())
            }
        }
    }
}
