use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds the maximum size of {max_bytes} bytes")]
    TooLong {
        field: &'static str,
        max_bytes: usize,
    },
    #[error("{field} exceeds the maximum item count of {max_items}")]
    TooMany {
        field: &'static str,
        max_items: usize,
    },
    #[error("{field} contains a duplicate value")]
    Duplicate { field: &'static str },
    #[error("{field} has an invalid value: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::Empty { field });
    }

    if value.len() > max_bytes {
        return Err(ValidationError::TooLong { field, max_bytes });
    }

    Ok(())
}

pub(crate) fn validate_bytes(
    value: &[u8],
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }

    if value.len() > max_bytes {
        return Err(ValidationError::TooLong { field, max_bytes });
    }

    Ok(())
}
