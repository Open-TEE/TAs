import qbs

DynamicLibrary {
    name: "tester_TA"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: ["tester_TA.c", "../include/tee_ta_properties.h"]
}

