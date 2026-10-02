use vollmacht_macos_key_probe::durable::*;

// Standard P-256 generator, no random key generation or Keychain calls.
fn public() -> Vec<u8> {
    let hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn id() -> KeyId {
    KeyId::new("0123456789abcdef0123456789abcdef").unwrap()
}
fn enrolled() -> Enrollment {
    Enrollment::restore(id(), PublicKey::parse(&public()).unwrap())
}

#[derive(Default)]
struct Fake {
    stored: Option<(String, Vec<u8>)>,
    calls: Vec<&'static str>,
    error: Option<BackendError>,
    export_error: Option<BackendError>,
    ambiguous: bool,
    invalid_created_key: bool,
}

impl Backend for Fake {
    type Handle = Vec<u8>;
    fn create_new(&mut self, id: &KeyId) -> Result<Self::Handle, BackendError> {
        self.calls.push("create");
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.stored.is_some() {
            return Err(BackendError::Duplicate);
        }
        let bytes = if self.invalid_created_key {
            vec![0; 65]
        } else {
            public()
        };
        self.stored = Some((id.as_str().to_owned(), bytes.clone()));
        Ok(bytes)
    }
    fn lookup(&mut self, id: &KeyId) -> Result<Lookup<Self::Handle>, BackendError> {
        self.calls.push("lookup");
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.ambiguous {
            return Ok(Lookup::Ambiguous);
        }
        Ok(match &self.stored {
            Some((name, bytes)) if name == id.as_str() => Lookup::One(bytes.clone()),
            _ => Lookup::Missing,
        })
    }
    fn public_key(&mut self, handle: &Self::Handle) -> Result<Vec<u8>, BackendError> {
        self.calls.push("export");
        match self.export_error {
            Some(error) => Err(error),
            None => Ok(handle.clone()),
        }
    }
}

#[test]
fn identifier_is_exact_and_namespaced() {
    assert_eq!(
        id().as_str(),
        "io.vollmacht.experimental.issuer.v1.0123456789abcdef0123456789abcdef"
    );
    for value in [
        "",
        "*",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcdef/",
        "../0123456789abcdef0123456789abc",
        "0123456789abcdef0123456789abcde\0",
    ] {
        assert_eq!(KeyId::new(value), Err(Error::InvalidId));
    }
}

#[test]
fn public_key_validates_shape_and_curve() {
    let valid = public();
    assert_eq!(
        PublicKey::parse(&valid).unwrap().as_bytes().as_slice(),
        valid
    );
    for invalid in [
        vec![],
        vec![4; 65],
        vec![0; 65],
        valid[..64].to_vec(),
        [valid.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(PublicKey::parse(&invalid), Err(Error::InvalidPublicKey));
    }
}

#[test]
fn create_pins_key_without_a_racy_preflight_lookup() {
    let mut backend = Fake::default();
    let opened = create(&mut backend, id()).unwrap();
    assert_eq!(opened.enrollment(), &enrolled());
    assert_eq!(opened.handle(), &public());
    assert_eq!(backend.calls, ["create", "export"]);
}

#[test]
fn restart_opens_existing_key_with_restored_trusted_metadata() {
    let mut first = Fake::default();
    let enrollment = create(&mut first, id()).unwrap().enrollment().clone();
    let restored = Enrollment::restore(
        enrollment.id().clone(),
        PublicKey::parse(enrollment.public_key().as_bytes()).unwrap(),
    );
    let mut restarted = Fake {
        stored: first.stored.take(),
        ..Fake::default()
    };
    assert_eq!(
        open(&mut restarted, &restored).unwrap().enrollment(),
        &enrollment
    );
    assert_eq!(restarted.calls, ["lookup", "export"]);
}

#[test]
fn missing_never_creates() {
    let mut backend = Fake::default();
    assert_eq!(open(&mut backend, &enrolled()).err(), Some(Error::Missing));
    assert_eq!(backend.calls, ["lookup"]);
    assert!(backend.stored.is_none());
}

#[test]
fn unrelated_identity_is_not_selected() {
    let mut backend = Fake {
        stored: Some(("unrelated".into(), public())),
        ..Fake::default()
    };
    assert_eq!(open(&mut backend, &enrolled()).err(), Some(Error::Missing));
    assert_eq!(backend.calls, ["lookup"]);
}

#[test]
fn ambiguous_never_selects_first_match() {
    let mut backend = Fake {
        ambiguous: true,
        ..Fake::default()
    };
    assert_eq!(
        open(&mut backend, &enrolled()).err(),
        Some(Error::Ambiguous)
    );
    assert_eq!(backend.calls, ["lookup"]);
}

#[test]
fn duplicate_creation_never_opens_or_replaces() {
    let mut backend = Fake::default();
    create(&mut backend, id()).unwrap();
    backend.calls.clear();
    let before = backend.stored.clone();
    assert_eq!(
        create(&mut backend, id()).err(),
        Some(Error::Backend(BackendError::Duplicate))
    );
    assert_eq!(backend.calls, ["create"]);
    assert_eq!(backend.stored, before);
}

#[test]
fn access_failures_propagate_without_retry_or_fallback() {
    for error in [
        BackendError::Denied,
        BackendError::Locked,
        BackendError::Cancelled,
        BackendError::Unsupported,
        BackendError::Unavailable,
        BackendError::Duplicate,
    ] {
        let mut backend = Fake {
            error: Some(error),
            ..Fake::default()
        };
        assert_eq!(
            create(&mut backend, id()).err(),
            Some(Error::Backend(error))
        );
        assert_eq!(backend.calls, ["create"]);
        backend.calls.clear();
        assert_eq!(
            open(&mut backend, &enrolled()).err(),
            Some(Error::Backend(error))
        );
        assert_eq!(backend.calls, ["lookup"]);
    }
}

#[test]
fn public_export_failure_keeps_orphan_for_explicit_recovery() {
    let mut backend = Fake {
        export_error: Some(BackendError::Denied),
        ..Fake::default()
    };
    assert_eq!(
        create(&mut backend, id()).err(),
        Some(Error::Backend(BackendError::Denied))
    );
    assert_eq!(backend.calls, ["create", "export"]);
    assert!(backend.stored.is_some());
    backend.calls.clear();
    assert_eq!(
        open(&mut backend, &enrolled()).err(),
        Some(Error::Backend(BackendError::Denied))
    );
    assert_eq!(backend.calls, ["lookup", "export"]);
}

#[test]
fn invalid_public_key_is_never_enrolled_or_opened() {
    let mut backend = Fake {
        invalid_created_key: true,
        ..Fake::default()
    };
    assert_eq!(
        create(&mut backend, id()).err(),
        Some(Error::InvalidPublicKey)
    );
    assert!(backend.stored.is_some());
    assert_eq!(
        open(&mut backend, &enrolled()).err(),
        Some(Error::InvalidPublicKey)
    );
}

#[test]
fn valid_but_substituted_key_is_rejected() {
    // Negating the generator's y coordinate gives another valid P-256 point.
    let mut other = public();
    let neg_y = "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a";
    for (target, pair) in other[33..]
        .iter_mut()
        .zip(neg_y.as_bytes().as_chunks::<2>().0.iter())
    {
        *target = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    PublicKey::parse(&other).unwrap();
    let mut backend = Fake {
        stored: Some((id().as_str().into(), other.clone())),
        ..Fake::default()
    };
    assert_eq!(
        open(&mut backend, &enrolled()).err(),
        Some(Error::PublicKeyMismatch)
    );
    assert_eq!(backend.calls, ["lookup", "export"]);
    assert_eq!(backend.stored.unwrap().1, other);
}
