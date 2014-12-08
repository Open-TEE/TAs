import qbs

DynamicLibrary {
    name: "crypto_tester_ta"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: ["crypto_tester_ta.c", "../include/tee_ta_properties.h"]
}
