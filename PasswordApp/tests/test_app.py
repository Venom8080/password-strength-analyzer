import pytest

from app import (
    app,
    check_password,
    generate_password,
    init_db,
    suggest_improved_password,
)


@pytest.fixture
def client(tmp_path):
    app.config["DATABASE"] = str(tmp_path / "test.db")
    app.config["SECRET_KEY"] = "test-secret"
    app.config["TESTING"] = True
    app.config["_db_initialized"] = False
    init_db()
    app.config["_db_initialized"] = True
    with app.test_client() as c:
        yield c


def register_and_login(client, name="Alice"):
    r = client.post("/register", json={"name": name})
    assert r.status_code == 200
    data = r.get_json()
    assert "user_number" in data and "password" in data
    lr = client.post(
        "/login",
        json={"user_number": data["user_number"], "password": data["password"]},
    )
    assert lr.status_code == 200
    return data


def test_check_password_empty():
    r = check_password("")
    assert r["score"] == 0
    assert r["status"] == "None"


def test_check_password_strong():
    r = check_password("Aa1!aaaaaaaa")
    assert r["status"] == "Strong"
    assert r["criteria"]["length"] is True
    assert r["criteria"]["upper"] is True
    assert r["criteria"]["lower"] is True
    assert r["criteria"]["number"] is True
    assert r["criteria"]["special"] is True


def test_api_check_post_no_suggested_in_response(client):
    rv = client.post(
        "/api/check",
        json={"password": "Short1!"},
        content_type="application/json",
    )
    assert rv.status_code == 200
    data = rv.get_json()
    assert "score" in data
    assert "status" in data
    assert "suggested_password" not in data


def test_api_suggest_requires_auth(client):
    rv = client.post("/api/suggest", json={"password": "hello"})
    assert rv.status_code == 401


def test_api_suggest_unique_when_not_saved(client):
    register_and_login(client)
    a = client.post("/api/suggest", json={"password": "hello"}).get_json()
    b = client.post("/api/suggest", json={"password": "hello"}).get_json()
    assert a["suggested_password"] != b["suggested_password"]


def test_api_suggest_returns_stored_after_save(client):
    register_and_login(client)
    s1 = client.post("/api/suggest", json={"password": "myorig"}).get_json()["suggested_password"]
    client.post(
        "/api/save",
        json={"original_password": "myorig", "suggested_password": s1},
    )
    s2 = client.post("/api/suggest", json={"password": "myorig"}).get_json()
    assert s2["from_storage"] is True
    assert s2["suggested_password"] == s1


def test_api_decrypt_after_save(client):
    register_and_login(client)
    sug = client.post("/api/suggest", json={"password": "orig1"}).get_json()["suggested_password"]
    client.post(
        "/api/save",
        json={"original_password": "orig1", "suggested_password": sug},
    )
    d = client.post("/api/decrypt", json={"original_password": "orig1"}).get_json()
    assert d["suggested_password"] == sug


def test_suggest_improved_password_strong():
    s = suggest_improved_password("weak")
    assert check_password(s)["status"] == "Strong"


def test_api_generate_post(client):
    rv = client.post(
        "/api/generate",
        json={"length": 12, "upper": True, "numbers": True, "symbols": True},
    )
    assert rv.status_code == 200
    data = rv.get_json()
    assert "password" in data
    assert len(data["password"]) == 12


def test_generate_password_respects_length():
    pw = generate_password(8, True, True, True)
    assert len(pw) == 8


def test_check_password_coerces_non_string():
    r = check_password(12345)
    assert r["criteria"]["number"] is True


def test_special_char_matches_punctuation():
    r = check_password("aaaaaaa`")
    assert r["criteria"]["special"] is True


def test_api_check_empty_body(client):
    rv = client.post("/api/check", data="not json", content_type="text/plain")
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["status"] == "None"


def test_api_generate_clamps_length(client):
    rv = client.post("/api/generate", json={"length": 999})
    assert rv.status_code == 200
    assert len(rv.get_json()["password"]) == 128


def test_api_generate_bool_string_false(client):
    rv = client.post(
        "/api/generate",
        json={"length": 10, "upper": "false", "numbers": True, "symbols": True},
    )
    assert rv.status_code == 200
    pw = rv.get_json()["password"]
    assert not any(c.isupper() for c in pw)


def test_register_login_json(client):
    r = client.post("/register", json={"name": "Bob"})
    assert r.status_code == 200
    j = r.get_json()
    lr = client.post(
        "/login",
        json={"user_number": j["user_number"], "password": j["password"]},
    )
    assert lr.status_code == 200


def test_register_simple_credentials_format(client):
    j = client.post("/register", json={"name": "Cred"}).get_json()
    assert j["user_number"].startswith("USER")
    assert j["password"].startswith("pass@-")
    assert "!" in j["password"]


def test_api_suggest_empty_password(client):
    register_and_login(client)
    rv = client.post("/api/suggest", json={"password": "   "})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "Empty password"


def test_api_save_empty_original(client):
    register_and_login(client)
    rv = client.post(
        "/api/save",
        json={"original_password": "", "suggested_password": "Ab1!aaaaaaaa"},
    )
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "Empty password"


def test_api_decrypt_empty(client):
    register_and_login(client)
    rv = client.post("/api/decrypt", json={"original_password": ""})
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "Empty password"


def test_login_form_redirects_to_choice(client):
    j = client.post("/register", json={"name": "Redir"}).get_json()
    rv = client.post(
        "/login",
        data={"user_number": j["user_number"], "password": j["password"]},
        follow_redirects=False,
    )
    assert rv.status_code == 302
    assert "/choice" in rv.headers.get("Location", "")


def test_dashboard_redirects_to_choice(client):
    register_and_login(client)
    rv = client.get("/dashboard", follow_redirects=False)
    assert rv.status_code == 302
    assert "/choice" in rv.headers.get("Location", "")


def test_choice_requires_login(client):
    rv = client.get("/choice", follow_redirects=False)
    assert rv.status_code == 302
