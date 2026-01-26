package com.auth0.jwt;

import java.util.Objects;

public class UserPojo {
    private String name;
    private int id;

    @SuppressWarnings("unused")
    public UserPojo() {
        //Required Empty Constructor
    }

    public UserPojo(String name, int id) {
        this.name = name;
        this.id = id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UserPojo userPojo = (UserPojo) o;

        return id == userPojo.id && (Objects.equals(name, userPojo.name));
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }
}