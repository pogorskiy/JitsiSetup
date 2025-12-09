"""Property-based tests for Auth Service.

Uses hypothesis library for property-based testing.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from hypothesis import given, strategies as st, settings, assume

from utils import parse_allowed_domains, is_domain_allowed, sign_state, verify_state, make_jitsi_jwt
import jwt


# Strategy for generating valid domain-like strings (non-empty, no commas)
domain_chars = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
)
domain_strategy = st.text(alphabet=domain_chars, min_size=1, max_size=50)


@given(st.lists(domain_strategy, min_size=0, max_size=10))
@settings(max_examples=100)
def test_domain_parsing_correctness(domains: list[str]):
    """
    **Feature: jitsi-google-auth-deploy, Property 1: Domain Parsing Correctness**
    **Validates: Requirements 4.1, 4.2**

    For any comma-separated string of domains, parsing SHALL produce a set
    containing all specified domains in lowercase, with whitespace trimmed.
    """
    # Filter out empty strings from the input domains
    non_empty_domains = [d for d in domains if d.strip()]

    # Build comma-separated string with random whitespace
    domains_str = ", ".join(domains)

    # Parse the domains
    result = parse_allowed_domains(domains_str)

    # Property 1: All non-empty domains should be in the result (lowercase)
    expected = {d.strip().lower() for d in non_empty_domains if d.strip()}

    assert result == expected, f"Expected {expected}, got {result}"



@given(st.lists(st.text(min_size=1, max_size=30), min_size=1, max_size=5))
@settings(max_examples=100)
def test_domain_parsing_lowercase(domains: list[str]):
    """
    **Feature: jitsi-google-auth-deploy, Property 1: Domain Parsing Correctness**
    **Validates: Requirements 4.1, 4.2**

    All parsed domains should be lowercase regardless of input case.
    """
    # Filter domains that don't contain commas (commas are delimiters)
    valid_domains = [d for d in domains if "," not in d and d.strip()]
    assume(len(valid_domains) > 0)

    domains_str = ",".join(valid_domains)
    result = parse_allowed_domains(domains_str)

    # All results should be lowercase
    for domain in result:
        assert domain == domain.lower(), f"Domain '{domain}' is not lowercase"


@given(st.lists(domain_strategy, min_size=1, max_size=5))
@settings(max_examples=100)
def test_domain_parsing_whitespace_trimmed(domains: list[str]):
    """
    **Feature: jitsi-google-auth-deploy, Property 1: Domain Parsing Correctness**
    **Validates: Requirements 4.1, 4.2**

    Whitespace around domains should be trimmed.
    """
    # Filter out empty domains
    valid_domains = [d for d in domains if d.strip()]
    assume(len(valid_domains) > 0)

    # Add random whitespace around domains
    domains_with_whitespace = [f"  {d}  " for d in valid_domains]
    domains_str = ",".join(domains_with_whitespace)

    result = parse_allowed_domains(domains_str)

    # No domain in result should have leading/trailing whitespace
    for domain in result:
        assert domain == domain.strip(), f"Domain '{domain}' has whitespace"


@given(st.text())
@settings(max_examples=100)
def test_domain_parsing_empty_handling(input_str: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 1: Domain Parsing Correctness**
    **Validates: Requirements 4.1, 4.2**

    Empty or whitespace-only input should return empty set.
    Empty segments between commas should be ignored.
    """
    result = parse_allowed_domains(input_str)

    # Result should always be a set
    assert isinstance(result, set)

    # No empty strings in result
    assert "" not in result

    # No whitespace-only strings in result
    for domain in result:
        assert domain.strip() == domain
        assert len(domain) > 0


# Strategy for generating valid email local parts
email_local_chars = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-"
)
email_local_strategy = st.text(alphabet=email_local_chars, min_size=1, max_size=30)


@given(
    email_local=email_local_strategy,
    domain=domain_strategy,
)
@settings(max_examples=100)
def test_case_insensitive_domain_matching(email_local: str, domain: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 2: Case-Insensitive Domain Matching**
    **Validates: Requirements 4.3**

    For any email address with a domain that matches an allowed domain
    (ignoring case), the domain check SHALL return true.
    """
    # Skip empty domains
    assume(domain.strip())

    # Create allowed domains set with lowercase domain
    allowed_domains = {domain.lower()}

    # Test with various case combinations of the same domain
    email_lower = f"{email_local}@{domain.lower()}"
    email_upper = f"{email_local}@{domain.upper()}"
    email_mixed = f"{email_local}@{domain.swapcase()}"

    # All case variations should match
    assert is_domain_allowed(
        email_lower, allowed_domains
    ), f"Lowercase domain '{domain.lower()}' should match"
    assert is_domain_allowed(
        email_upper, allowed_domains
    ), f"Uppercase domain '{domain.upper()}' should match"
    assert is_domain_allowed(
        email_mixed, allowed_domains
    ), f"Mixed case domain '{domain.swapcase()}' should match"


@given(
    email_local=email_local_strategy,
    allowed_domain=domain_strategy,
    email_domain=domain_strategy,
)
@settings(max_examples=100)
def test_domain_matching_rejects_non_matching(
    email_local: str, allowed_domain: str, email_domain: str
):
    """
    **Feature: jitsi-google-auth-deploy, Property 2: Case-Insensitive Domain Matching**
    **Validates: Requirements 4.3**

    For any email address with a domain that does NOT match any allowed domain,
    the domain check SHALL return false.
    """
    # Skip empty domains
    assume(allowed_domain.strip())
    assume(email_domain.strip())

    # Ensure domains are actually different (case-insensitive)
    assume(allowed_domain.lower() != email_domain.lower())

    allowed_domains = {allowed_domain.lower()}
    email = f"{email_local}@{email_domain}"

    assert not is_domain_allowed(
        email, allowed_domains
    ), f"Email domain '{email_domain}' should NOT match allowed '{allowed_domain}'"



# Strategy for generating valid room names (non-empty strings without colons at the end)
room_name_chars = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)
room_name_strategy = st.text(alphabet=room_name_chars, min_size=1, max_size=100)


@given(room=room_name_strategy)
@settings(max_examples=100)
def test_state_signing_roundtrip(room: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 3: State Signing Round-Trip**
    **Validates: Requirements 5.1, 5.2**

    For any room name, signing the state and then verifying it SHALL return
    the original room name.
    """
    # Set up a test STATE_SECRET for the test
    os.environ["STATE_SECRET"] = "test-secret-key-for-property-testing"
    
    try:
        # Sign the state
        signed_state = sign_state(room)
        
        # Verify the state and get back the room name
        recovered_room = verify_state(signed_state)
        
        # The recovered room should match the original
        assert recovered_room == room, f"Expected room '{room}', got '{recovered_room}'"
    finally:
        # Clean up environment variable
        if "STATE_SECRET" in os.environ:
            del os.environ["STATE_SECRET"]


# Strategy for generating a single character modification
hex_chars = "0123456789abcdef"


@given(
    room=room_name_strategy,
    position=st.integers(min_value=0, max_value=63),  # SHA256 hex is 64 chars
    new_char=st.sampled_from(hex_chars)
)
@settings(max_examples=100)
def test_tampered_state_rejection(room: str, position: int, new_char: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 4: Tampered State Rejection**
    **Validates: Requirements 5.3**

    For any valid signed state, modifying any character in the signature
    SHALL cause verification to fail.
    """
    from fastapi import HTTPException
    
    # Set up a test STATE_SECRET for the test
    os.environ["STATE_SECRET"] = "test-secret-key-for-property-testing"
    
    try:
        # Sign the state
        signed_state = sign_state(room)
        
        # Extract the signature part (after the last colon)
        parts = signed_state.rsplit(":", 1)
        room_part, signature = parts
        
        # Ensure we're actually changing the character (skip if same)
        if position < len(signature) and signature[position] == new_char:
            # Pick a different character to ensure we actually tamper
            for c in hex_chars:
                if c != signature[position]:
                    new_char = c
                    break
        
        # Tamper with the signature at the given position
        if position < len(signature):
            tampered_signature = (
                signature[:position] + new_char + signature[position + 1:]
            )
            tampered_state = f"{room_part}:{tampered_signature}"
            
            # Verification should fail with HTTPException
            try:
                verify_state(tampered_state)
                # If we get here, verification didn't fail - that's a bug
                assert False, f"Tampered state was accepted: {tampered_state}"
            except HTTPException as e:
                # Expected behavior - verification should fail
                assert e.status_code == 400, f"Expected 400, got {e.status_code}"
                assert "Invalid state signature" in e.detail, f"Unexpected error: {e.detail}"
    finally:
        # Clean up environment variable
        if "STATE_SECRET" in os.environ:
            del os.environ["STATE_SECRET"]


# Strategy for generating valid email addresses
email_strategy = st.builds(
    lambda local, domain: f"{local}@{domain}",
    local=email_local_strategy,
    domain=domain_strategy,
)

# Strategy for generating display names (non-empty strings)
name_chars = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_."
)
name_strategy = st.text(alphabet=name_chars, min_size=1, max_size=50)


@given(
    email=email_strategy,
    name=name_strategy,
    room=room_name_strategy,
)
@settings(max_examples=100)
def test_jwt_structure_validity(email: str, name: str, room: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 5: JWT Structure Validity**
    **Validates: Requirements 2.3**

    For any valid email, name, and room combination, the generated JWT SHALL
    contain all required Jitsi claims (aud, iss, sub, room, context.user)
    and moderator SHALL be true.
    """
    # Skip empty inputs
    assume(email.strip())
    assume(name.strip())
    assume(room.strip())
    
    # Set up required Jitsi environment variables for the test
    os.environ["JITSI_APP_ID"] = "test-app-id"
    os.environ["JITSI_APP_SECRET"] = "test-app-secret-key"
    os.environ["JITSI_DOMAIN"] = "meet.example.com"
    
    try:
        # Generate the JWT
        token = make_jitsi_jwt(email, name, room)
        
        # Decode the JWT with verification
        decoded = jwt.decode(
            token,
            "test-app-secret-key",
            algorithms=["HS256"],
            audience="test-app-id",
            options={"verify_signature": True}
        )
        
        # Property: JWT must contain all required Jitsi claims
        
        # 1. aud (audience) must be present and equal to app_id
        assert "aud" in decoded, "JWT missing 'aud' claim"
        assert decoded["aud"] == "test-app-id", f"Expected aud='test-app-id', got '{decoded['aud']}'"
        
        # 2. iss (issuer) must be present and equal to app_id
        assert "iss" in decoded, "JWT missing 'iss' claim"
        assert decoded["iss"] == "test-app-id", f"Expected iss='test-app-id', got '{decoded['iss']}'"
        
        # 3. sub (subject) must be present
        assert "sub" in decoded, "JWT missing 'sub' claim"
        
        # 4. room must be present
        assert "room" in decoded, "JWT missing 'room' claim"
        
        # 5. context.user must be present with required fields
        assert "context" in decoded, "JWT missing 'context' claim"
        assert "user" in decoded["context"], "JWT missing 'context.user' claim"
        
        user_context = decoded["context"]["user"]
        
        # 6. context.user must contain email
        assert "email" in user_context, "JWT missing 'context.user.email'"
        assert user_context["email"] == email, f"Expected email='{email}', got '{user_context['email']}'"
        
        # 7. context.user must contain name
        assert "name" in user_context, "JWT missing 'context.user.name'"
        assert user_context["name"] == name, f"Expected name='{name}', got '{user_context['name']}'"
        
        # 8. context.user.moderator must be True
        assert "moderator" in user_context, "JWT missing 'context.user.moderator'"
        assert user_context["moderator"] is True, f"Expected moderator=True, got {user_context['moderator']}"
        
        # 9. iat (issued at) must be present and be an integer
        assert "iat" in decoded, "JWT missing 'iat' claim"
        assert isinstance(decoded["iat"], int), f"Expected iat to be int, got {type(decoded['iat'])}"
        
        # 10. nbf (not before) must be present and be an integer
        assert "nbf" in decoded, "JWT missing 'nbf' claim"
        assert isinstance(decoded["nbf"], int), f"Expected nbf to be int, got {type(decoded['nbf'])}"
        
        # 11. exp (expiration) must be present and be an integer
        assert "exp" in decoded, "JWT missing 'exp' claim"
        assert isinstance(decoded["exp"], int), f"Expected exp to be int, got {type(decoded['exp'])}"
        
        # 12. exp must be greater than iat (token has positive lifetime)
        assert decoded["exp"] > decoded["iat"], "Token expiration must be after issued time"
        
    finally:
        # Clean up environment variables
        for var in ["JITSI_APP_ID", "JITSI_APP_SECRET", "JITSI_DOMAIN"]:
            if var in os.environ:
                del os.environ[var]
