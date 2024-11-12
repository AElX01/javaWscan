package web_vulnerabilities_constants;

/*
    enum used to output the right message and the status of each finding on a website
 */

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
    StatusCodes(String outputMessage) { this.outputMessage = outputMessage; }
    public String toString() { return outputMessage; }
}
