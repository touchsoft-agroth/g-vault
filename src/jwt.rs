pub struct JWT {
    headers: Vec<Header>,
    claims: Vec<Claim>,
    signature: Option<Signature>
}

impl JWT {
    pub fn new() -> Self {
        JWT {
            headers: vec![],
            claims: vec![],
            signature: None
        }
    }

    pub fn add_header(&mut self, name: &str, value: &str) {
        let header = Header {
            name: name.to_string(),
            value: value.to_string()
        };

        self.headers.push(header);
    }

    pub fn get_header(&self, name: &str) -> Option<&Header>{
        self.headers
            .iter()
            .find(|header| header.name == name)
    }

    pub fn add_claim(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    pub fn get_claim(&self, name: &str) -> Option<&Claim> {
        self.claims
            .iter()
            .find(|claim| claim.name == name)
    }

    pub fn sign(&mut self, secret_key: &str) {
        // todo: create json string of header and payload, then sign using hmac-sha256
    }
}

#[test]
pub fn new_test() {
    let mut jwt = JWT::new();
    jwt.add_header("typ", "JWT");
    jwt.add_header("alg", "HS256");

    let typ_header = jwt.get_header("typ").unwrap();
    assert_eq!(typ_header.name, "typ");
    assert_eq!(typ_header.value, "JWT");

    let alg_header = jwt.get_header("alg").unwrap();
    assert_eq!(alg_header.name, "alg");
    assert_eq!(alg_header.value, "HS256");

    jwt.add_claim(Claim::from_string("sub", "123456789"));
    let sub_claim = jwt.get_claim("sub").unwrap();
    assert_eq!(sub_claim.as_string().unwrap(), "123456789");

    jwt.add_claim(Claim::from_string("name", "John Doe"));
    let name_claim = jwt.get_claim("name").unwrap();
    assert_eq!(name_claim.as_string().unwrap(), "John Doe");

    jwt.add_claim(Claim::from_bool("admin", true));
    let admin_claim = jwt.get_claim("admin").unwrap();
    assert_eq!(admin_claim.as_bool().unwrap(), true);

    jwt.add_claim(Claim::from_int("iat", 1673362819));
    let iat_claim = jwt.get_claim("iat").unwrap();
    assert_eq!(iat_claim.as_int().unwrap(), 1673362819);

    jwt.add_claim(Claim::from_int("exp", 1673366419));
    let exp_claim = jwt.get_claim("exp").unwrap();
    assert_eq!(exp_claim.as_int().unwrap(), 1673366419);
}

#[test]
pub fn from_bytes_test() {
    // let input_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3MzM2MjgxOSwiZXhwIjoxNjczMzY2NDE5fQ.tmKUlXXsQ9X5RY8rv62G7P95BEJzlQQnAT-v9TLmC2o".as_bytes();
    //
    // let header_typ = "JWT";
    // let header_alg = "HS256";
    // let claim_sub = "123456789";
    // let claim_name = "John Doe";
    // let claim_admin = true;
    // let claim_iat = 1673362819;
    // let claim_exp = 1673366419;
    //
    //let jwt = from_bytes(input_string);

    // rest of testing here. do not fill this out
}

pub struct Header {
    pub name: String,
    pub value: String
}

pub struct Claim {
    pub name: String,
    pub value: ClaimValue
}

impl Claim {
    pub fn from_string(name: &str, value: &str) -> Self {
        Claim
        {
            name: name.to_string(),
            value: ClaimValue::String(value.to_string())
        }
    }

    pub fn as_string(&self) -> Option<&String> {
        match &self.value {
            ClaimValue::String(s) => Some(s),
            _ => None
        }
    }

    pub fn from_float(name: &str, value: f64) -> Self {
        Claim
        {
            name: name.to_string(),
            value: ClaimValue::Float(value)
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match &self.value {
            ClaimValue::Float(f) => Some(f.clone()),
            _ => None
        }
    }

    pub fn from_int(name: &str, value: i64) -> Self {
        Claim
        {
            name: name.to_string(),
            value: ClaimValue::Int(value)
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match &self.value {
            ClaimValue::Int(i) => Some(i.clone()),
            _ => None
        }
    }

    pub fn from_bool(name: &str, value: bool) -> Self {
        Claim
        {
            name: name.to_string(),
            value: ClaimValue::Boolean(value)
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match &self.value {
            ClaimValue::Boolean(b) => Some(b.clone()),
            _ => None
        }
    }
}

enum ClaimValue {
    String(String),
    Float(f64),
    Int(i64),
    Boolean(bool)
}

pub struct Signature {
    pub value: [u8]
}