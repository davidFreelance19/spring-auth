package com.authentication.app.services;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.authentication.app.domain.services.IEmailService;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
public class EmailServiceImpl implements IEmailService {

    private final JavaMailSender mailSender;

    EmailServiceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void sendEmailVerifyAccount(String email, String token) throws MessagingException {
        String htmlMsg = """
                        <h1>Welcome to Our Application</h1>

                        <p>Steps for verify your account: </p>
                        <ol>
                            <li>Visit our page: <a href="http://localhost:3000/api/auth/verify-account/%s">verify account</a></li>
                        </ol>
                        <div class="warning">
                            <p><strong>Important:</strong></p>
                            <ul>
                                <li>If you didn't request this account, please contact our IT support immediately at support@apptest.com.</li>
                                <li>Never share your login information with anyone.</li>
                            </ul>
                        </div>
                        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                """;

        MimeMessage message = mailSender.createMimeMessage();
        try {

            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(email);
            helper.setSubject("Welcome to our app");
            helper.setText(String.format(htmlMsg, token), true); // true indicates HTML
            helper.setFrom("noreply@apptest.com");

            mailSender.send(message);
        } catch (MessagingException e) {
            throw new MessagingException("Error sending email");
         }
    }
    
    @Override
    public void sendEmailRecupereAccount(String email, String token) throws MessagingException {
        String htmlMsg = """
                        <h1>Password Reset Request</h1>
                        <p>We received a request to reset your password for your account associated with this email address.</p>

                        <div class="info">
                            <p><strong>Email:</strong> %s</p>
                        </div>
                        <p>To reset your password, please click the link below:</p>
                        <p><a href="http://localhost:3000/api/auth/change-password/%s">Reset Your Password</a></p>
                        <p>If you didn't request a password reset, you can safely ignore this email.</p>

                        <div class="warning">
                            <p><strong>Important:</strong></p>
                            <ul>
                                <li>For security reasons, this link will expire in 5 minutes.</li>
                            </ul>
                        </div>
                        <p>If you have any questions or need further assistance, feel free to contact our support team.</p>
                """;

        MimeMessage message = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(email);
            helper.setSubject("Password Reset Request");
            helper.setText(String.format(htmlMsg, email, token), true); // true indicates HTML
            helper.setFrom("noreply@apptest.com");

            mailSender.send(message);
        } catch (MessagingException e) {
           throw new MessagingException("Error sending email");
        }
    }
}
