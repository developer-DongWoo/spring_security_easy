package security.securityFrame.exception;

import lombok.Getter;

public enum ExceptionCode {
    // MEMBER
    BAD_REQUEST(400, "Bad Request!"),
    NOT_FOUND_ERROR(404, "Not Found Error!")
    ;

    @Getter
    private int status;

    @Getter
    private String message;

    ExceptionCode(int code, String message) {
        this.status = code;
        this.message = message;
    }
}
