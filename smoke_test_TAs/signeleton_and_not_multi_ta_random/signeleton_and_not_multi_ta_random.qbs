import qbs

DynamicLibrary {
    name: "signeleton_and_not_multi_ta_random"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: ["signeleton_and_not_multi_ta_random.c", "../../include/tee_ta_properties.h"]
}