package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Authentication details of a login callback; carries where to return to from the
 * authorization request to the success handler.
 */
public class PortvaktLoginDetails extends WebAuthenticationDetails {
  private static final long serialVersionUID = 1L;

  private String returnTo;

  public PortvaktLoginDetails(HttpServletRequest request) {
    super(request);
  }

  public String getReturnTo() {
    return returnTo;
  }

  void setReturnTo(String returnTo) {
    this.returnTo = returnTo;
  }
}
