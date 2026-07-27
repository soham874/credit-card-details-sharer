package com.soham.ccshareapp.repository;

import com.soham.ccshareapp.model.Card;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CardRepository extends JpaRepository<Card, String> {
}
