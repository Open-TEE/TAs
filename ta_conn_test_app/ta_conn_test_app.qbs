import qbs

DynamicLibrary {
    name: "ta_conn_test_app"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "TAs"
    }

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN","_FORTIFY_SOURCE=2"]

    files: ["conn_test_ctl.h",
            "conn_test_ctl.c",
            "ta_conn_test_app.c",
            "../include/tee_ta_properties.h"]
}
