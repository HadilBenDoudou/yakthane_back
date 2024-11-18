package com.example.demo.controller;

public class UserLoginRequest {
    private String email;
    private String cin;

    // Constructeur par défaut
    public UserLoginRequest() {
    }

    // Getters et Setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getCin() {
        return cin;
    }

    public void setCin(String cin) {
        this.cin = cin;
    }
}
