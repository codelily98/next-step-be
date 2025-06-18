package com.next_step_be.next_step_be.domain;

public enum Role {
    USER("일반 사용자"),
    ADMIN("관리자");

    private final String label;

    Role(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
