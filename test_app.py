import io, os, re, tempfile
os.environ.update(FLASK_SECRET_KEY="x"*32, S3_BUCKET="test-bucket", AWS_REGION="ap-south-1",
                  AWS_ACCESS_KEY_ID="t", AWS_SECRET_ACCESS_KEY="t",
                  DB_PATH=tempfile.mktemp(suffix=".db"))
from moto import mock_aws
from werkzeug.security import generate_password_hash

with mock_aws():
    import boto3, app
    boto3.client("s3", region_name="ap-south-1").create_bucket(
        Bucket="test-bucket", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    con = app.db(); con.execute("INSERT INTO users (username,password) VALUES (?,?)",
        ("alice", generate_password_hash("pw123"))); con.commit(); con.close()
    c = app.app.test_client()
    tok = lambda html: re.search(r'name="_csrf" value="(\w+)"', html).group(1)
    ok = lambda name, cond: print(("PASS " if cond else "FAIL ") + name) or (cond or exit(1))

    ok("dashboard requires login", c.get("/dashboard").status_code == 302)
    t = tok(c.get("/login").text)
    ok("login without csrf rejected", c.post("/login", data={"username":"alice","password":"pw123"}).status_code == 400)
    ok("bad password rejected", "Invalid" in c.post("/login", data={"username":"alice","password":"no","_csrf":t}, follow_redirects=True).text)
    c.post("/login", data={"username":"alice","password":"pw123","_csrf":t})
    page = c.get("/dashboard"); ok("login -> dashboard", page.status_code == 200)
    t = tok(page.text)

    pdf = b"%PDF-1.4 hello world"
    r = c.post("/upload", data={"file": (io.BytesIO(pdf), "cert.pdf"), "_csrf": t},
               content_type="multipart/form-data", follow_redirects=True)
    ok("upload pdf listed", "cert.pdf" in r.text)
    s3 = boto3.client("s3", region_name="ap-south-1")
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="test-bucket")["Contents"]]
    ok("file exists in S3", len(keys) == 1)
    ok("served file stored with SSE", s3.head_object(Bucket="test-bucket", Key=keys[0]).get("ServerSideEncryption") == "AES256")

    r = c.post("/upload", data={"file": (io.BytesIO(b"MZ evil"), "x.pdf"), "_csrf": t},
               content_type="multipart/form-data", follow_redirects=True)
    ok("fake pdf rejected", "does not match" in r.text)
    r = c.post("/upload", data={"file": (io.BytesIO(b"hi"), "x.exe"), "_csrf": t},
               content_type="multipart/form-data", follow_redirects=True)
    ok("bad extension rejected", "Only PDF" in r.text)
    r = c.post("/upload", data={"file": (io.BytesIO(b"%PDF"+b"0"*(6*1024*1024)), "big.pdf"), "_csrf": t},
               content_type="multipart/form-data", follow_redirects=True)
    ok("oversize rejected", "too large" in r.text)

    ok("view -> presigned inline", "inline" in c.get("/view/1").headers["Location"])
    ok("download -> presigned attachment", "attachment" in c.get("/download/1").headers["Location"])

    # another user must not access alice's doc
    con = app.db(); con.execute("INSERT INTO users (username,password) VALUES (?,?)", ("bob", generate_password_hash("b"))); con.commit(); con.close()
    c2 = app.app.test_client(); t2 = tok(c2.get("/login").text)
    c2.post("/login", data={"username":"bob","password":"b","_csrf":t2})
    ok("other user gets 404", c2.get("/download/1").status_code == 404)
    ok("delete without csrf rejected", c.post("/delete/1").status_code == 400)

    r = c.post("/delete/1", data={"_csrf": t}, follow_redirects=True)
    ok("delete removes from list", "cert.pdf" not in r.text or "Deleted" in r.text)
    ok("delete removes from S3", "Contents" not in s3.list_objects_v2(Bucket="test-bucket"))
    c.get("/logout"); ok("logout ends session", c.get("/dashboard").status_code == 302)
print("ALL TESTS PASSED")
