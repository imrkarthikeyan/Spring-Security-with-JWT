package com.karthikeyan.jwt.PayLoad.Request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.Set;

public class SignupRequest {
    @NotBlank
    @Size(max=50)
    @Email(regexp = "^[a-z0-9,_$+-]+@[a-z0-9,-]+\\.[a-z]{2,3}$")
    private String username;

    private Set<String> role;

    @NotBlank
    @Size(min=6, max=30)
    private String password;

    public String getUsername(){
        return username;
    }

    public void setUsername(String username){
        this.username = username;
    }

    public String getPassword(){
        return password;
    }

    public void setPassword(String password){
        this.password=password;
    }

    public Set<String> getRole(){
        return this.role;
    }

    public void setRole(Set<String> role){
        this.role=role;
    }
}
