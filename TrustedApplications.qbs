import qbs

Project {
    name: "TrustedApplications"
    references: [
        "ta_conn_test_app/ta_conn_test_app.qbs",
        "smoke_test_TAs/smoke_test_TAs.qbs",
        "example_digest_ta/example_digest_ta.qbs",
	"param_conn_test/param_conn_test.qbs",
	"usr_study_ta/usr_study_ta.qbs",
    ]
}
