package de.aittr.bio_marketplace.domain.entity;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.util.Objects;

@Entity
@Table(name = "product")
public class Product {

    // --- FIELDS ---

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "title", nullable = false)
    @NotNull(message = "Product title cannot be null")
    @NotBlank(message = "Product title cannot be empty")
    @Pattern(
            regexp = "[A-Z][a-z ]{2,}",
            message = "Product title should be at least three characters length and start with capital letter"
    )
    private String title;

    @Column(name = "description")
    // TODO: add swagger annotations
    private String description;

    @Column(name = "image")
    private String image;
    // TODO: add swagger annotations

    @Column(name = "price")
    @DecimalMin(
            value = "1.00",
            message = "Product price should be greater or equal than 1"
    )
    @DecimalMax(
            value = "1000.00",
            inclusive = false,
            message = "Product price should lesser than 1000"
    )
    private BigDecimal price;

    @Column(name = "status")
    private String status;
    // TODO: add swagger annotations

    @Column(name = "category_id")
    @Schema(description = "Category identifier", example = "1")
    private Long categoryId;

    @Column(name = "seller_id")
    @Schema(description = "Seller identifier", example = "1")
    private Long sellerId;

    // --- CONSTRUCTORS ---

    public Product() {
    }

    public Product(Long id, String title, String description, String image, BigDecimal price, String status, Long categoryId, Long sellerId) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.image = image;
        this.price = price;
        this.status = status;
        this.categoryId = categoryId;
        this.sellerId = sellerId;
    }

// --- METHODS ---

    // --- Getters and setters ---

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Long getCategoryId() {
        return categoryId;
    }

    public void setCategoryId(Long categoryId) {
        this.categoryId = categoryId;
    }

    public Long getSellerId() {
        return sellerId;
    }

    public void setSellerId(Long sellerId) {
        this.sellerId = sellerId;
    }

    // --- Equals and hashcode ---

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Product product = (Product) o;
        return Objects.equals(id, product.id) && Objects.equals(title, product.title) && Objects.equals(description, product.description) && Objects.equals(image, product.image) && Objects.equals(price, product.price) && Objects.equals(status, product.status) && Objects.equals(categoryId, product.categoryId) && Objects.equals(sellerId, product.sellerId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, title, description, image, price, status, categoryId, sellerId);
    }

    /* TODO: add the following fields:
    - images
    - rating
    - quantity
    - attributes
    - reviews
    - dateProduction
    - dateExpiration
*/

}
