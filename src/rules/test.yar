rule TestRule {
    strings:
        $hello = "hello"

    condition:
        $hello
}