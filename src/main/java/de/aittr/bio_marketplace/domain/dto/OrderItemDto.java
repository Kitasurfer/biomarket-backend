package de.aittr.bio_marketplace.domain.dto;

import de.aittr.bio_marketplace.domain.entity.Order;

import java.math.BigDecimal;

public class OrderItemDto {

    // --- FIELDS ---
    private Long id;
    private Long productId;
    private String productName;
    private BigDecimal quantity;
    private BigDecimal unitPrice;

    // --- METHODS ---

    // --- Getters and setters ---

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getProductId() {
        return productId;
    }

    public void setProductId(Long productId) {
        this.productId = productId;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public BigDecimal getQuantity() {
        return quantity;
    }

    public void setQuantity(BigDecimal quantity) {
        this.quantity = quantity;
    }

    public BigDecimal getUnitPrice() {
        return unitPrice;
    }

    public void setUnitPrice(BigDecimal unitPrice) {
        this.unitPrice = unitPrice;
    }
}