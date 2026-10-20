package com.automantle.api.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {
    @GetMapping({"/", "/profiles/{profileId}"})
    public String dashboard() {
        return "forward:/index.html";
    }
}
