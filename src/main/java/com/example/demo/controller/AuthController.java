package com.example.demo.controller;

import com.example.demo.Modele.SignUpStep1Request;
import com.example.demo.Modele.SignUpStep2Request;
import com.example.demo.Modele.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.EmailService;
import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest) {
        try {
            User user = userService.authenticateUser(loginRequest.getEmail(), loginRequest.getPassword());
            return ResponseEntity.ok("Login successful!");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
    @PostMapping("/signup/step1")
    public ResponseEntity<?> signUpStep1(@RequestBody SignUpStep1Request request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body("Email is already taken.");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword()); // Hachez le mot de passe en production
        user.setStep(1);
        userRepository.save(user);

        return ResponseEntity.ok("Step 1 successful, proceed to step 2.");
    }

    @PostMapping("/signup/step2")
    public ResponseEntity<?> signUpStep2(@RequestBody SignUpStep2Request request) {
        User user = userRepository.findByEmail(request.getEmail());
        if (user == null) {
            return ResponseEntity.badRequest().body("User not found.");
        }

        if (user.getStep() != 1) {
            return ResponseEntity.badRequest().body("Invalid step. Please complete step 1 first.");
        }

        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhoneNumber(request.getPhoneNumber());
        user.setAddress(request.getAddress());
        user.setStep(2);

        userRepository.save(user);
        return ResponseEntity.ok("Sign-up completed successfully!");
    }
    @Autowired
    private EmailService emailService;
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        // Vérifier si l'utilisateur existe
        User user = userRepository.findByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Email not found.");
        }

        // Générer un mot de passe temporaire
        String temporaryPassword = userService.generateTemporaryPassword(8);

        // Mettre à jour le mot de passe de l'utilisateur avec le mot de passe temporaire
        user.setPassword(temporaryPassword);  // Pas de hachage ici
        userRepository.save(user);

        // Envoyer l'email avec le mot de passe temporaire
        String emailBody = "Votre nouveau mot de passe temporaire est : " + temporaryPassword + ". Il est valide pendant 24 heures.";
        emailService.sendSimpleMessage(user.getEmail(), "Réinitialisation du mot de passe", emailBody);

        return ResponseEntity.ok("Temporary password sent to your email.");
    }



}
