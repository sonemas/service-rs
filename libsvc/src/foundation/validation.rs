use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub struct FieldValidationError(String);

impl Display for FieldValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for FieldValidationError{}

impl From<String> for FieldValidationError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for FieldValidationError {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Creates a field with validation upon parsing.
/// 
/// Input:
/// - The field name
/// - The field's base type
/// - The validator, which is a function returning a bool to represent whether 
/// validation was successful or not
/// - The error message, which will be prepended by the given value
/// 
/// The created struct implements the Debug and Display trait, as well as
/// the AsRef trait to the base type.
#[macro_export]
macro_rules! validated_field {
    ( $name:ident, $base_type:ty, $val:expr, $error:expr) => {

        #[derive(Debug)]
        #[cfg(feature = "serde")] #[derive(serde::Serialize, serde::Deserialize)]
        pub struct $name($base_type);

        impl $name {
            pub fn parse(v: $base_type) -> Result<$name, $crate::foundation::validation::FieldValidationError> {
                if $val(&v) {
                    Ok(Self(v))
                } else {
                    Err(format!("{} {}", v, $error).into())
                }
            }
        }

        impl AsRef<$base_type> for $name {
            fn as_ref(&self) -> &$base_type {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    }
}

/// Creates a field with validation upon parsing and an alternative ref type.
/// 
/// Input:
/// - The field name
/// - The field's base type
/// - The AsRef type
/// - The validator, which is a function returning a bool to represent whether 
/// validation was successful or not
/// - The error message, which will be prepended by the given value
/// 
/// The created struct implements the Debug and Display trait, as well as
/// the AsRef trait to the ref type.
#[macro_export]
macro_rules! validated_field_with_ref_type {
    ( $name:ident, $base_type:ty, $ref_type:ty, $val:expr, $error:expr ) => {

        #[derive(Debug)]
        #[cfg(feature = "serde")] #[derive(serde::Serialize, serde::Deserialize)]
        pub struct $name($base_type);

        impl $name {
            pub fn parse(v: $base_type) -> Result<$name, $crate::foundation::validation::FieldValidationError> {
                if $val(&v) {
                    Ok(Self(v))
                } else {
                    Err(format!("{} {}", v, $error).into())
                }
            }
        }

        impl AsRef<$ref_type> for $name {
            fn as_ref(&self) -> &$ref_type {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    }
}
