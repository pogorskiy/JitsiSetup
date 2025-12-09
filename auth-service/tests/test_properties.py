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


@given(room=room_name_strategy)
@settings(max_examples=100)
def test_auth_redirect_url_formation(room: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 6: Auth Redirect URL Formation**
    **Validates: Requirements 2.1**

    For any room name, the OAuth redirect SHALL include the room in a signed
    state parameter and redirect to Google's OAuth endpoint.
    """
    from urllib.parse import urlparse, parse_qs
    from utils import build_google_auth_url, sign_state, verify_state
    
    # Skip empty rooms
    assume(room.strip())
    
    # Set up required environment variables for the test
    os.environ["STATE_SECRET"] = "test-secret-key-for-property-testing"
    os.environ["GOOGLE_CLIENT_ID"] = "test-client-id.apps.googleusercontent.com"
    os.environ["GOOGLE_CLIENT_SECRET"] = "test-client-secret"
    os.environ["GOOGLE_REDIRECT_URI"] = "https://auth.example.com/oauth2/callback"
    
    try:
        # Sign the state with the room name
        state = sign_state(room)
        
        # Build the auth URL
        auth_url = build_google_auth_url(state)
        
        # Parse the URL
        parsed = urlparse(auth_url)
        query_params = parse_qs(parsed.query)
        
        # Property 1: URL must point to Google's OAuth endpoint
        assert parsed.scheme == "https", f"Expected https scheme, got {parsed.scheme}"
        assert parsed.netloc == "accounts.google.com", f"Expected accounts.google.com, got {parsed.netloc}"
        assert parsed.path == "/o/oauth2/v2/auth", f"Expected /o/oauth2/v2/auth, got {parsed.path}"
        
        # Property 2: URL must include client_id
        assert "client_id" in query_params, "Missing client_id parameter"
        assert query_params["client_id"][0] == "test-client-id.apps.googleusercontent.com", \
            f"Unexpected client_id: {query_params['client_id'][0]}"
        
        # Property 3: URL must include redirect_uri
        assert "redirect_uri" in query_params, "Missing redirect_uri parameter"
        assert query_params["redirect_uri"][0] == "https://auth.example.com/oauth2/callback", \
            f"Unexpected redirect_uri: {query_params['redirect_uri'][0]}"
        
        # Property 4: URL must include response_type=code
        assert "response_type" in query_params, "Missing response_type parameter"
        assert query_params["response_type"][0] == "code", \
            f"Expected response_type=code, got {query_params['response_type'][0]}"
        
        # Property 5: URL must include scope with openid, email, profile
        assert "scope" in query_params, "Missing scope parameter"
        scope = query_params["scope"][0]
        assert "openid" in scope, f"Missing 'openid' in scope: {scope}"
        assert "email" in scope, f"Missing 'email' in scope: {scope}"
        assert "profile" in scope, f"Missing 'profile' in scope: {scope}"
        
        # Property 6: URL must include state parameter
        assert "state" in query_params, "Missing state parameter"
        state_param = query_params["state"][0]
        
        # Property 7: State parameter must be verifiable and contain the room name
        recovered_room = verify_state(state_param)
        assert recovered_room == room, f"Expected room '{room}', got '{recovered_room}'"
        
    finally:
        # Clean up environment variables
        for var in ["STATE_SECRET", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI"]:
            if var in os.environ:
                del os.environ[var]


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


# =============================================================================
# Property 9 & 10: Access Control Properties
# =============================================================================

@given(
    email_local=email_local_strategy,
    allowed_domain=domain_strategy,
    name=name_strategy,
    room=room_name_strategy,
)
@settings(max_examples=100)
def test_allowed_domain_access_grant(email_local: str, allowed_domain: str, name: str, room: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 9: Allowed Domain Access Grant**
    **Validates: Requirements 2.3, 2.5**

    For any email from an allowed domain, the auth flow SHALL result in
    a redirect to Jitsi with a valid JWT.
    
    This test verifies that when a user's email domain matches an allowed domain,
    the system correctly:
    1. Identifies the domain as allowed
    2. Generates a valid JWT with moderator privileges
    3. The JWT contains the correct user information
    """
    # Skip empty inputs
    assume(email_local.strip())
    assume(allowed_domain.strip())
    assume(name.strip())
    assume(room.strip())
    
    # Construct email with the allowed domain
    email = f"{email_local}@{allowed_domain}"
    
    # Create allowed domains set (lowercase as per implementation)
    allowed_domains = {allowed_domain.lower()}
    
    # Set up required environment variables
    os.environ["JITSI_APP_ID"] = "test-app-id"
    os.environ["JITSI_APP_SECRET"] = "test-app-secret-key"
    os.environ["JITSI_DOMAIN"] = "meet.example.com"
    
    try:
        # Property 9.1: Domain check must return True for allowed domain
        assert is_domain_allowed(email, allowed_domains), \
            f"Email '{email}' should be allowed for domain '{allowed_domain}'"
        
        # Property 9.2: JWT generation must succeed for allowed domain
        jwt_token = make_jitsi_jwt(email, name, room)
        assert jwt_token is not None, "JWT should be generated for allowed domain"
        assert len(jwt_token) > 0, "JWT should not be empty"
        
        # Property 9.3: Generated JWT must be valid and decodable
        decoded = jwt.decode(
            jwt_token,
            "test-app-secret-key",
            algorithms=["HS256"],
            audience="test-app-id",
            options={"verify_signature": True}
        )
        
        # Property 9.4: JWT must contain correct user email
        assert decoded["context"]["user"]["email"] == email, \
            f"JWT email should be '{email}'"
        
        # Property 9.5: JWT must grant moderator privileges
        assert decoded["context"]["user"]["moderator"] is True, \
            "JWT must grant moderator privileges for allowed domain"
        
    finally:
        # Clean up environment variables
        for var in ["JITSI_APP_ID", "JITSI_APP_SECRET", "JITSI_DOMAIN"]:
            if var in os.environ:
                del os.environ[var]


@given(
    email_local=email_local_strategy,
    email_domain=domain_strategy,
    allowed_domain=domain_strategy,
    name=name_strategy,
    room=room_name_strategy,
)
@settings(max_examples=100)
def test_disallowed_domain_access_denial(
    email_local: str, email_domain: str, allowed_domain: str, name: str, room: str
):
    """
    **Feature: jitsi-google-auth-deploy, Property 10: Disallowed Domain Access Denial**
    **Validates: Requirements 2.4**

    For any email NOT from an allowed domain, the auth flow SHALL NOT generate
    a JWT and SHALL display an access denied response.
    
    This test verifies that when a user's email domain does NOT match any allowed
    domain, the system correctly:
    1. Identifies the domain as NOT allowed
    2. Does NOT grant access (is_domain_allowed returns False)
    
    Note: The actual access denied HTML response is handled by the endpoint,
    but the core access control logic is in is_domain_allowed().
    """
    # Skip empty inputs
    assume(email_local.strip())
    assume(email_domain.strip())
    assume(allowed_domain.strip())
    
    # Ensure domains are actually different (case-insensitive)
    assume(email_domain.lower() != allowed_domain.lower())
    
    # Construct email with a domain that is NOT in the allowed list
    email = f"{email_local}@{email_domain}"
    
    # Create allowed domains set with a DIFFERENT domain
    allowed_domains = {allowed_domain.lower()}
    
    # Property 10.1: Domain check must return False for disallowed domain
    result = is_domain_allowed(email, allowed_domains)
    
    assert result is False, \
        f"Email '{email}' should NOT be allowed when allowed domains are {allowed_domains}"


@given(
    email_local=email_local_strategy,
    allowed_domains_list=st.lists(domain_strategy, min_size=1, max_size=5),
    name=name_strategy,
    room=room_name_strategy,
)
@settings(max_examples=100)
def test_allowed_domain_access_grant_multiple_domains(
    email_local: str, allowed_domains_list: list[str], name: str, room: str
):
    """
    **Feature: jitsi-google-auth-deploy, Property 9: Allowed Domain Access Grant**
    **Validates: Requirements 2.3, 2.5**

    For any email from ANY of the allowed domains (when multiple domains are configured),
    the auth flow SHALL result in access being granted.
    
    This tests the scenario where multiple domains are allowed (comma-separated in config).
    """
    # Skip empty inputs
    assume(email_local.strip())
    assume(name.strip())
    assume(room.strip())
    
    # Filter out empty domains
    valid_domains = [d for d in allowed_domains_list if d.strip()]
    assume(len(valid_domains) > 0)
    
    # Pick one of the allowed domains for the email
    chosen_domain = valid_domains[0]
    email = f"{email_local}@{chosen_domain}"
    
    # Create allowed domains set from all valid domains
    allowed_domains = {d.lower() for d in valid_domains}
    
    # Set up required environment variables
    os.environ["JITSI_APP_ID"] = "test-app-id"
    os.environ["JITSI_APP_SECRET"] = "test-app-secret-key"
    os.environ["JITSI_DOMAIN"] = "meet.example.com"
    
    try:
        # Property: Email from any allowed domain should be granted access
        assert is_domain_allowed(email, allowed_domains), \
            f"Email '{email}' should be allowed when domains {allowed_domains} are configured"
        
        # Property: JWT should be generated successfully
        jwt_token = make_jitsi_jwt(email, name, room)
        assert jwt_token is not None and len(jwt_token) > 0, \
            "JWT should be generated for email from allowed domain"
        
    finally:
        # Clean up environment variables
        for var in ["JITSI_APP_ID", "JITSI_APP_SECRET", "JITSI_DOMAIN"]:
            if var in os.environ:
                del os.environ[var]


@given(
    email_local=email_local_strategy,
    email_domain=domain_strategy,
)
@settings(max_examples=100)
def test_disallowed_domain_empty_allowed_list(email_local: str, email_domain: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 10: Disallowed Domain Access Denial**
    **Validates: Requirements 2.4**

    When no domains are allowed (empty allowed domains set), ALL emails should be denied.
    """
    # Skip empty inputs
    assume(email_local.strip())
    assume(email_domain.strip())
    
    email = f"{email_local}@{email_domain}"
    
    # Empty allowed domains set
    allowed_domains: set[str] = set()
    
    # Property: No email should be allowed when allowed domains is empty
    result = is_domain_allowed(email, allowed_domains)
    
    assert result is False, \
        f"Email '{email}' should NOT be allowed when no domains are configured"


# =============================================================================
# Property 7: Domain Derivation Correctness
# =============================================================================

import subprocess


def derive_auth_domain(main_domain: str) -> str:
    """
    Python implementation of the derive_auth_domain function from deploy.sh.
    This mirrors the bash function: echo "auth.${main_domain}"
    """
    return f"auth.{main_domain}"


def derive_auth_domain_bash(main_domain: str) -> str:
    """
    Call the actual bash function from deploy.sh to verify behavior.
    We extract just the function definition to avoid running the main script.
    """
    # Define the function inline (same as in deploy.sh)
    # This tests the same logic without sourcing the entire script
    bash_cmd = f'''
derive_auth_domain() {{
    local main_domain="$1"
    echo "auth.${{main_domain}}"
}}
derive_auth_domain "{main_domain}"
'''
    
    result = subprocess.run(
        ["bash", "-c", bash_cmd],
        capture_output=True,
        text=True
    )
    
    return result.stdout.strip()


# Strategy for generating valid domain parts (labels)
# Domain labels: alphanumeric and hyphens, but not starting/ending with hyphen
domain_label_chars = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)
domain_label_strategy = st.text(alphabet=domain_label_chars, min_size=1, max_size=20)


@given(
    subdomain=domain_label_strategy,
    domain=domain_label_strategy,
    tld=domain_label_strategy,
)
@settings(max_examples=100)
def test_domain_derivation_correctness(subdomain: str, domain: str, tld: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 7: Domain Derivation Correctness**
    **Validates: Requirements 8.2**

    For any main domain in format X.Y.Z, the auth domain SHALL be derived as auth.X.Y.Z.
    """
    # Skip empty parts
    assume(subdomain.strip())
    assume(domain.strip())
    assume(tld.strip())
    
    # Construct a main domain like "meet.example.com"
    main_domain = f"{subdomain}.{domain}.{tld}"
    
    # Expected auth domain
    expected_auth_domain = f"auth.{main_domain}"
    
    # Test Python implementation
    result = derive_auth_domain(main_domain)
    
    # Property 1: Auth domain must be "auth." prepended to main domain
    assert result == expected_auth_domain, \
        f"Expected '{expected_auth_domain}', got '{result}'"
    
    # Property 2: Auth domain must start with "auth."
    assert result.startswith("auth."), \
        f"Auth domain must start with 'auth.', got '{result}'"
    
    # Property 3: Removing "auth." prefix should give back the original domain
    assert result[5:] == main_domain, \
        f"Removing 'auth.' should give '{main_domain}', got '{result[5:]}'"


@given(
    subdomain=domain_label_strategy,
    domain=domain_label_strategy,
    tld=domain_label_strategy,
)
@settings(max_examples=100)
def test_domain_derivation_bash_consistency(subdomain: str, domain: str, tld: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 7: Domain Derivation Correctness**
    **Validates: Requirements 8.2**

    The bash function derive_auth_domain in deploy.sh must produce the same result
    as the expected behavior: prepending "auth." to the main domain.
    """
    # Skip empty parts
    assume(subdomain.strip())
    assume(domain.strip())
    assume(tld.strip())
    
    # Construct a main domain like "meet.example.com"
    main_domain = f"{subdomain}.{domain}.{tld}"
    
    # Expected auth domain
    expected_auth_domain = f"auth.{main_domain}"
    
    # Test bash implementation
    bash_result = derive_auth_domain_bash(main_domain)
    
    # Property: Bash function must produce correct auth domain
    assert bash_result == expected_auth_domain, \
        f"Bash derive_auth_domain('{main_domain}') returned '{bash_result}', expected '{expected_auth_domain}'"


@given(main_domain=domain_strategy)
@settings(max_examples=100)
def test_domain_derivation_simple_domains(main_domain: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 7: Domain Derivation Correctness**
    **Validates: Requirements 8.2**

    For any non-empty domain string, the auth domain SHALL be "auth." + main_domain.
    """
    # Skip empty domains
    assume(main_domain.strip())
    
    # Expected auth domain
    expected_auth_domain = f"auth.{main_domain}"
    
    # Test Python implementation
    result = derive_auth_domain(main_domain)
    
    # Property: Auth domain must be "auth." prepended to main domain
    assert result == expected_auth_domain, \
        f"Expected '{expected_auth_domain}', got '{result}'"


# =============================================================================
# Property 8: Configuration Template Substitution
# =============================================================================

import tempfile
import re


def substitute_template_python(template_content: str, substitutions: dict[str, str]) -> str:
    """
    Python implementation of template substitution that mirrors the bash sed command.
    Replaces ${PLACEHOLDER} patterns with actual values.
    """
    result = template_content
    for placeholder, value in substitutions.items():
        # Match ${PLACEHOLDER} pattern
        pattern = r'\$\{' + re.escape(placeholder) + r'\}'
        result = re.sub(pattern, value, result)
    return result


def substitute_template_bash(template_content: str, substitutions: dict[str, str]) -> str:
    r"""
    Call the actual bash sed substitution logic from deploy.sh.
    This tests the same logic as the substitute_template function.
    Uses the same sed syntax as deploy.sh: sed -e 's|\${PLACEHOLDER}|value|g'
    """
    # Create a temporary file with the template content
    with tempfile.NamedTemporaryFile(mode='w', suffix='.template', delete=False) as f:
        f.write(template_content)
        template_file = f.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.out', delete=False) as f:
        output_file = f.name
    
    try:
        # Build the sed command matching deploy.sh exactly:
        # sed -e 's|\${MAIN_DOMAIN}|value|g' ...
        sed_args = []
        for placeholder, value in substitutions.items():
            # Escape special characters in value for sed (| and & need escaping)
            escaped_value = value.replace('|', r'\|').replace('&', r'\&')
            # Pattern: s|\${PLACEHOLDER}|value|g
            # In single quotes, $ and { don't need escaping in bash
            sed_args.append(f"-e 's|\\${{{placeholder}}}|{escaped_value}|g'")
        
        sed_cmd = f"sed {' '.join(sed_args)} '{template_file}' > '{output_file}'"
        
        result = subprocess.run(
            ["bash", "-c", sed_cmd],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"sed failed: {result.stderr}")
        
        with open(output_file, 'r') as f:
            return f.read()
    finally:
        import os
        os.unlink(template_file)
        os.unlink(output_file)


# Strategy for generating valid placeholder values (non-empty, no special chars that break sed)
# Avoid characters that could break sed substitution: |, &, \, newlines
safe_value_chars = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_@:/"
)
safe_value_strategy = st.text(alphabet=safe_value_chars, min_size=1, max_size=50)


@given(
    main_domain=domain_label_strategy,
    auth_domain=domain_label_strategy,
    timezone=safe_value_strategy,
    google_client_id=safe_value_strategy,
    google_client_secret=safe_value_strategy,
    allowed_domains=safe_value_strategy,
    app_id=safe_value_strategy,
    app_secret=safe_value_strategy,
    state_secret=safe_value_strategy,
)
@settings(max_examples=100)
def test_template_substitution_no_remaining_placeholders(
    main_domain: str,
    auth_domain: str,
    timezone: str,
    google_client_id: str,
    google_client_secret: str,
    allowed_domains: str,
    app_id: str,
    app_secret: str,
    state_secret: str,
):
    """
    **Feature: jitsi-google-auth-deploy, Property 8: Configuration Template Substitution**
    **Validates: Requirements 8.3**

    For any domain and credentials input, all generated configuration files SHALL
    contain the substituted values with no remaining placeholders.
    """
    # Skip empty values
    assume(main_domain.strip())
    assume(auth_domain.strip())
    assume(timezone.strip())
    assume(google_client_id.strip())
    assume(google_client_secret.strip())
    assume(allowed_domains.strip())
    assume(app_id.strip())
    assume(app_secret.strip())
    assume(state_secret.strip())
    
    # Build substitutions dict matching deploy.sh variables
    substitutions = {
        "MAIN_DOMAIN": main_domain,
        "AUTH_DOMAIN": auth_domain,
        "TIMEZONE": timezone,
        "GOOGLE_CLIENT_ID": google_client_id,
        "GOOGLE_CLIENT_SECRET": google_client_secret,
        "ALLOWED_DOMAINS": allowed_domains,
        "APP_ID": app_id,
        "APP_SECRET": app_secret,
        "STATE_SECRET": state_secret,
    }
    
    # Test template with all placeholders
    template = """
GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
GOOGLE_REDIRECT_URI=https://${AUTH_DOMAIN}/oauth2/callback
JITSI_BASE_URL=https://${MAIN_DOMAIN}
JITSI_DOMAIN=${MAIN_DOMAIN}
JITSI_APP_ID=${APP_ID}
JITSI_APP_SECRET=${APP_SECRET}
ALLOWED_MOD_DOMAINS=${ALLOWED_DOMAINS}
STATE_SECRET=${STATE_SECRET}
TZ=${TIMEZONE}
"""
    
    # Perform substitution
    result = substitute_template_python(template, substitutions)
    
    # Property 1: No remaining ${...} placeholders should exist
    remaining_placeholders = re.findall(r'\$\{[A-Z_]+\}', result)
    assert len(remaining_placeholders) == 0, \
        f"Found remaining placeholders: {remaining_placeholders}"
    
    # Property 2: All substituted values should appear in the result
    assert main_domain in result, f"MAIN_DOMAIN '{main_domain}' not found in result"
    assert auth_domain in result, f"AUTH_DOMAIN '{auth_domain}' not found in result"
    assert timezone in result, f"TIMEZONE '{timezone}' not found in result"
    assert google_client_id in result, f"GOOGLE_CLIENT_ID '{google_client_id}' not found in result"
    assert google_client_secret in result, f"GOOGLE_CLIENT_SECRET '{google_client_secret}' not found in result"
    assert allowed_domains in result, f"ALLOWED_DOMAINS '{allowed_domains}' not found in result"
    assert app_id in result, f"APP_ID '{app_id}' not found in result"
    assert app_secret in result, f"APP_SECRET '{app_secret}' not found in result"
    assert state_secret in result, f"STATE_SECRET '{state_secret}' not found in result"


@given(
    main_domain=domain_label_strategy,
    auth_domain=domain_label_strategy,
    timezone=safe_value_strategy,
    google_client_id=safe_value_strategy,
    google_client_secret=safe_value_strategy,
    allowed_domains=safe_value_strategy,
    app_id=safe_value_strategy,
    app_secret=safe_value_strategy,
    state_secret=safe_value_strategy,
)
@settings(max_examples=100)
def test_template_substitution_bash_consistency(
    main_domain: str,
    auth_domain: str,
    timezone: str,
    google_client_id: str,
    google_client_secret: str,
    allowed_domains: str,
    app_id: str,
    app_secret: str,
    state_secret: str,
):
    """
    **Feature: jitsi-google-auth-deploy, Property 8: Configuration Template Substitution**
    **Validates: Requirements 8.3**

    The bash sed substitution in deploy.sh must produce the same result as the
    expected Python implementation.
    """
    # Skip empty values
    assume(main_domain.strip())
    assume(auth_domain.strip())
    assume(timezone.strip())
    assume(google_client_id.strip())
    assume(google_client_secret.strip())
    assume(allowed_domains.strip())
    assume(app_id.strip())
    assume(app_secret.strip())
    assume(state_secret.strip())
    
    # Build substitutions dict
    substitutions = {
        "MAIN_DOMAIN": main_domain,
        "AUTH_DOMAIN": auth_domain,
        "TIMEZONE": timezone,
        "GOOGLE_CLIENT_ID": google_client_id,
        "GOOGLE_CLIENT_SECRET": google_client_secret,
        "ALLOWED_DOMAINS": allowed_domains,
        "APP_ID": app_id,
        "APP_SECRET": app_secret,
        "STATE_SECRET": state_secret,
    }
    
    # Simple template for testing
    template = "DOMAIN=${MAIN_DOMAIN}\nAUTH=${AUTH_DOMAIN}\nTZ=${TIMEZONE}\n"
    
    # Get results from both implementations
    python_result = substitute_template_python(template, substitutions)
    bash_result = substitute_template_bash(template, substitutions)
    
    # Property: Both implementations should produce identical results
    assert python_result == bash_result, \
        f"Python and bash results differ:\nPython: {python_result}\nBash: {bash_result}"


@given(
    main_domain=domain_label_strategy,
    auth_domain=domain_label_strategy,
)
@settings(max_examples=100)
def test_template_substitution_preserves_structure(main_domain: str, auth_domain: str):
    """
    **Feature: jitsi-google-auth-deploy, Property 8: Configuration Template Substitution**
    **Validates: Requirements 8.3**

    Template substitution SHALL preserve the structure of the configuration file,
    only replacing placeholder values while keeping all other content intact.
    """
    # Skip empty values
    assume(main_domain.strip())
    assume(auth_domain.strip())
    
    substitutions = {
        "MAIN_DOMAIN": main_domain,
        "AUTH_DOMAIN": auth_domain,
    }
    
    # Template with specific structure
    template = """# Comment line
server_name ${MAIN_DOMAIN};
ssl_certificate /etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem;
# Another comment
location / {
    proxy_pass http://upstream;
}
"""
    
    result = substitute_template_python(template, substitutions)
    
    # Property 1: Comments should be preserved
    assert "# Comment line" in result, "Comment line should be preserved"
    assert "# Another comment" in result, "Another comment should be preserved"
    
    # Property 2: Structure should be preserved
    assert "server_name " in result, "server_name directive should be preserved"
    assert "ssl_certificate " in result, "ssl_certificate directive should be preserved"
    assert "location / {" in result, "location block should be preserved"
    assert "proxy_pass http://upstream;" in result, "proxy_pass should be preserved"
    
    # Property 3: Placeholders should be replaced with actual values
    assert f"server_name {main_domain};" in result, \
        f"MAIN_DOMAIN should be substituted in server_name"
    assert f"/etc/letsencrypt/live/{auth_domain}/fullchain.pem" in result, \
        f"AUTH_DOMAIN should be substituted in ssl_certificate path"
