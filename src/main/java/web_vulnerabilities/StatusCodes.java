package web_vulnerabilities;

public enum StatusCodes {
    INFO("INFO"),
    WARNING("WARNING"),
    CRITICAL("CRITICAL"),
    ERROR("ERROR"),

    INFO_LOG("[" + java.time.LocalTime.now() + "]" + " [" + StatusCodes.INFO + "] "),
    WARNING_LOG("[" + java.time.LocalTime.now() + "]" + " [" + StatusCodes.WARNING + "] "),
    CRITICAL_LOG("[" + java.time.LocalTime.now() + "]" + " [" + StatusCodes.CRITICAL + "] "),
    ERROR_LOG("[" + java.time.LocalTime.now() + "]" + " [" + StatusCodes.ERROR + "] ");

    private final String outputMessage;
    private StatusCodes(String outputMessage) { this.outputMessage = outputMessage; }
    public String toString() {
        return outputMessage;
    }
}
