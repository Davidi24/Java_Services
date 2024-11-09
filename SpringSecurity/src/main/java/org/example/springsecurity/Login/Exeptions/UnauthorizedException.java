package org.example.springsecurity.Login.Exeptions;

public class UnauthorizedException extends RuntimeException {

    public UnauthorizedException(String message) {
        super(message);
    }

    public UnauthorizedException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnauthorizedException(Throwable cause) {
        super(cause);
    }

    @Override
    public String toString() {
        return "UnauthorizedException: " + getMessage();
    }
}
