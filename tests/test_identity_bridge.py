"""Tests for Identity Bridge (SPIFFE, OAuth)."""

from agent_passport.identity_bridge import (
    parse_spiffe_id,
    import_spiffe_svid,
    map_oauth_scopes,
    import_oauth_token,
)
import pytest


class TestParseSPIFFEID:
    def test_basic_parse(self):
        result = parse_spiffe_id("spiffe://cluster.example.com/workload/api")
        assert result["trust_domain"] == "cluster.example.com"
        assert result["workload_path"] == "/workload/api"

    def test_deep_path(self):
        result = parse_spiffe_id("spiffe://prod.corp/ns/default/sa/web")
        assert result["trust_domain"] == "prod.corp"
        assert result["workload_path"] == "/ns/default/sa/web"

    def test_rejects_non_spiffe(self):
        with pytest.raises(ValueError, match="must start with spiffe://"):
            parse_spiffe_id("https://example.com")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must start with spiffe://"):
            parse_spiffe_id("")

    def test_rejects_missing_workload(self):
        with pytest.raises(ValueError, match="missing trust domain or workload path"):
            parse_spiffe_id("spiffe://cluster.example.com")


class TestImportSPIFFESVID:
    def test_basic_import(self):
        att = import_spiffe_svid({
            "spiffe_id": "spiffe://cluster.local/workload/api",
            "expires_at": "2030-01-01T00:00:00Z",
        })
        assert att["provider"] == "cluster.local"
        assert att["subjectClass"] == "workload"
        assert att["verificationMethod"] == "spiffe_bundle"
        assert len(att["subjectIdHash"]) == 64

    def test_with_x509_cert(self):
        att = import_spiffe_svid({
            "spiffe_id": "spiffe://cluster.local/workload/api",
            "x509_cert": "PEM-DATA-HERE",
            "expires_at": "2030-01-01T00:00:00Z",
        })
        assert att["verificationMethod"] == "x509"

    def test_rejects_missing_expires(self):
        with pytest.raises(ValueError, match="expires_at is required"):
            import_spiffe_svid({
                "spiffe_id": "spiffe://cluster.local/workload/api",
            })

    def test_deterministic_hash(self):
        svid = {
            "spiffe_id": "spiffe://cluster.local/workload/api",
            "expires_at": "2030-01-01T00:00:00Z",
        }
        h1 = import_spiffe_svid(svid)["subjectIdHash"]
        h2 = import_spiffe_svid(svid)["subjectIdHash"]
        assert h1 == h2


class TestMapOAuthScopes:
    def test_wildcard_mapping(self):
        result = map_oauth_scopes(["read:users", "write:posts"])
        assert result == ["data_read", "data_write"]

    def test_passthrough_unknown(self):
        result = map_oauth_scopes(["custom:scope"])
        assert "custom:scope" in result

    def test_deduplication(self):
        result = map_oauth_scopes(["read:users", "read:posts"])
        assert result.count("data_read") == 1

    def test_custom_mapping(self):
        result = map_oauth_scopes(["read:users"], {"read:*": "custom_read"})
        assert result == ["custom_read"]

    def test_empty_scopes(self):
        assert map_oauth_scopes([]) == []


class TestImportOAuthToken:
    def test_basic_import(self):
        result = import_oauth_token({
            "sub": "user-123",
            "iss": "https://auth.example.com",
            "scope": "read:users write:posts",
            "exp": 2000000000,
        })
        assert result["agent_id"].startswith("agent-oauth-")
        assert "data_read" in result["delegation_scope"]
        assert "data_write" in result["delegation_scope"]
        assert "2033" in result["expires_at"]

    def test_deterministic_agent_id(self):
        token = {
            "sub": "user-123",
            "iss": "https://auth.example.com",
            "scope": "read:users",
            "exp": 2000000000,
        }
        id1 = import_oauth_token(token)["agent_id"]
        id2 = import_oauth_token(token)["agent_id"]
        assert id1 == id2

    def test_different_subs_different_ids(self):
        t1 = {"sub": "user-1", "iss": "https://a.com", "scope": "", "exp": 2000000000}
        t2 = {"sub": "user-2", "iss": "https://a.com", "scope": "", "exp": 2000000000}
        assert import_oauth_token(t1)["agent_id"] != import_oauth_token(t2)["agent_id"]

    def test_rejects_missing_sub(self):
        with pytest.raises(ValueError, match="sub claim"):
            import_oauth_token({"iss": "a", "exp": 1, "scope": ""})

    def test_rejects_missing_iss(self):
        with pytest.raises(ValueError, match="iss claim"):
            import_oauth_token({"sub": "a", "exp": 1, "scope": ""})

    def test_rejects_invalid_exp(self):
        with pytest.raises(ValueError, match="exp claim"):
            import_oauth_token({"sub": "a", "iss": "b", "exp": 0, "scope": ""})
