"""Property-based tests for Auth Service.

Uses hypothesis library for property-based testing.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from hypothesis import given, strategies as st, settings, assume

from utils import parse_allowed_domains, is_domain_allowed


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
