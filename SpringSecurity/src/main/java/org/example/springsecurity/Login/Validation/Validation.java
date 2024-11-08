package org.example.springsecurity.Login.Validation;
import org.example.springsecurity.Login.model.Users;
import java.util.regex.Pattern;

public  class Validation {

    // Regex patterns for validation
    private static final String EMAIL_PATTERN = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";
    private static final String PHONE_PATTERN = "^[0-9]{10}$";
    private static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-zA-Z]).{8,}$";

    public static String validateUser(Users user) {
        if (user.getEmail() == null || !Pattern.matches(EMAIL_PATTERN, user.getEmail())) {
            return "Invalid email format";
        }
        if (user.getPassword() == null || !Pattern.matches(PASSWORD_PATTERN, user.getPassword())) {
            return "Password must be at least 8 characters long and contain both letters and numbers";
        }
        if (user.getPhoneNumer() != null && !Pattern.matches(PHONE_PATTERN, user.getPhoneNumer())) {
            return "Phone number must be exactly 10 digits";
        }

        return "";
    }
}
