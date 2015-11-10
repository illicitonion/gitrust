macro_rules! try_or_string {
    ( $result:expr ) => {
        match $result {
            Ok(r) => r,
            Err(e) => return Err(e.description().to_owned()),
        }
    }
}

macro_rules! get_json_string {
    ( $obj:expr, $key:expr ) => {
        {
            let val = match $obj.find($key) {
                Some(v) => v,
                None => return Err(format!("missing {}", $key)),
            };
            let s = match val.as_string() {
                Some(v) => v,
                None => return Err(format!("not a string: {}", $key)),
            };
            s
        }
    }
}
