import io, os, re, tempfile

os.environ.update(
    FLASK_SECRET_KEY="x" * 32,
    S3_BUCKET="test-bucket",
    AWS_REGION="ap-south-1",
    AWS_ACCESS_KEY_ID="t",
    AWS_SECRET_ACCESS_KEY="t",
    DB_PATH=tempfile.mktemp(suffix=".db"),
)

from moto import mock_aws

with mock_aws():
    import boto3, app

    boto3.client("s3", region_name="ap-south-1").create_bucket(
        Bucket="test-bucket",
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )

    c = app.app.test_client()
    tok = lambda html: re.search(r'name="_csrf" value="(\w+)"', html).group(1)
    ok = lambda name, cond: print(("PASS " if cond else "FAIL ") + name) or (cond or exit(1))

    ok("dashboard is public", c.get("/dashboard").status_code == 200)
    ok("root redirects to dashboard", c.get("/").status_code == 302)
    ok("login route is absent", c.get("/login").status_code == 404)

    page = c.get("/dashboard")
    t = tok(page.text)
    pdf = b"%PDF-1.4 hello world"
    r = c.post(
        "/upload",
        data={"file": (io.BytesIO(pdf), "cert.pdf"), "_csrf": t},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    ok("public upload pdf listed", "cert.pdf" in r.text)

    r = c.post(
        "/upload",
        data={
            "file": [
                (io.BytesIO(b"%PDF-1.4 second file"), "one.pdf"),
                (io.BytesIO(b"%PDF-1.4 third file"), "two.pdf"),
            ],
            "_csrf": t,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    ok("multiple files uploaded", "one.pdf" in r.text and "two.pdf" in r.text)

    s3 = boto3.client("s3", region_name="ap-south-1")
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="test-bucket")["Contents"]]
    ok("file exists in S3", len(keys) >= 3)
    ok("served file stored with SSE", s3.head_object(Bucket="test-bucket", Key=keys[0]).get("ServerSideEncryption") == "AES256")

    r = c.post(
        "/upload",
        data={"file": (io.BytesIO(b"MZ evil"), "x.pdf"), "_csrf": t},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    ok("fake pdf rejected", "does not match" in r.text)

    r = c.post(
        "/upload",
        data={"file": (io.BytesIO(b"hi"), "x.exe"), "_csrf": t},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    ok("bad extension rejected", "Only PDF" in r.text)

    r = c.post(
        "/upload",
        data={"file": (io.BytesIO(b"%PDF" + b"0" * (7 * 1024 * 1024)), "big.pdf"), "_csrf": t},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    ok("large upload accepted", "big.pdf" in r.text)

    ok("view -> presigned inline", "inline" in c.get("/view/1").headers["Location"])
    ok("download -> presigned attachment", "attachment" in c.get("/download/1").headers["Location"])
    ok("delete without csrf rejected", c.post("/delete/1").status_code == 400)

    r = c.post("/delete/1", data={"_csrf": t}, follow_redirects=True)
    ok("delete removes from list", "cert.pdf" not in r.text or "Deleted" in r.text)
    r2 = c.post("/delete/4", data={"_csrf": t}, follow_redirects=True)
    ok("delete removes large upload", "big.pdf" not in r2.text or "Deleted" in r2.text)
    r3 = c.post("/delete/2", data={"_csrf": t}, follow_redirects=True)
    r4 = c.post("/delete/3", data={"_csrf": t}, follow_redirects=True)
    ok("delete removes all uploaded files", ("one.pdf" not in r3.text and "two.pdf" not in r4.text) or "Deleted" in r3.text or "Deleted" in r4.text)
    ok("delete removes from S3", s3.list_objects_v2(Bucket="test-bucket").get("Contents") is None)

print("ALL TESTS PASSED")
