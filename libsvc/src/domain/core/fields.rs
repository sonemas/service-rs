use validator::validate_email;
use crate::validated_field_with_ref_type;

validated_field_with_ref_type!{Email, String, str, validate_email, "is not a valid email"}
