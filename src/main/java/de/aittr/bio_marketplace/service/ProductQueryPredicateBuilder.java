package de.aittr.bio_marketplace.service;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.Predicate;
import de.aittr.bio_marketplace.domain.entity.ProductStatus;
import de.aittr.bio_marketplace.domain.entity.QProduct;
import org.apache.commons.lang3.StringUtils;

import java.math.BigDecimal;

public class ProductQueryPredicateBuilder {

    private final BooleanBuilder predicate;
    private final QProduct product;

    public ProductQueryPredicateBuilder(BooleanBuilder predicate, QProduct product) {
        this.predicate = predicate;
        this.product = product;
    }

    public static ProductQueryPredicateBuilder builder() {
        final BooleanBuilder builder = new BooleanBuilder();
        final QProduct product = QProduct.product;
        return new ProductQueryPredicateBuilder(builder, product);
    }

    // Search by title or description
    public ProductQueryPredicateBuilder byNameOrDescription(String search) {
        if (StringUtils.isNoneBlank(search)) {
            String searchPattern = "%" + search.toLowerCase() + "%";
            this.predicate
                    .and(this.product.title.likeIgnoreCase(searchPattern)
                            .or(this.product.description.likeIgnoreCase(searchPattern)));
        }
        return this;
    }

    // Filter by active status
    public ProductQueryPredicateBuilder andStatusActive() {
        this.predicate
                .and(this.product.status.eq(ProductStatus.ACTIVE));
        return this;
    }

    // Filter by category
    public ProductQueryPredicateBuilder byCategoryId(Long categoryId) {
        if (categoryId != null) {
            this.predicate
                    .and(this.product.categoryId.eq(categoryId));
        }
        return this;
    }

    // Filter by price range
    public ProductQueryPredicateBuilder byPriceRange(BigDecimal minPrice, BigDecimal maxPrice) {

        if (minPrice != null) {
            if (minPrice.compareTo(BigDecimal.ZERO) < 0) {
                throw new IllegalArgumentException("Minimum price cannot be negative: " + minPrice);
            }
            this.predicate.and(this.product.price.goe(minPrice));
        }

        if (maxPrice != null) {
            if (maxPrice.compareTo(BigDecimal.ZERO) < 0) {
                throw new IllegalArgumentException("Maximum price cannot be negative: " + maxPrice);
            }
            this.predicate.and(this.product.price.loe(maxPrice));
        }

        if (minPrice != null && maxPrice != null && minPrice.compareTo(maxPrice) > 0) {
            throw new IllegalArgumentException("Minimum price (" + minPrice + ") cannot be greater than maximum price (" + maxPrice + ")");
        }

        return this;
    }

    // Filter by seller
    public ProductQueryPredicateBuilder bySellerId(Long sellerId) {
        if (sellerId != null) {
            this.predicate
                    .and(this.product.seller.id.eq(sellerId));
        }
        return this;
    }

    // Filter by minimum rating
    public ProductQueryPredicateBuilder byMinRating(Double ratingMin) {
        if (ratingMin != null) {
            if (ratingMin < 1.00 || ratingMin > 5.00) {
                throw new IllegalArgumentException("Minimum rating must be between 1.00 and 5.00: " + ratingMin);
            }
            this.predicate.and(this.product.rating.goe(ratingMin));
        }
        return this;
    }

    // Filter by stock availability
    public ProductQueryPredicateBuilder byInStock(Boolean inStock) {
        if (inStock != null) {
            this.predicate.and(this.product.inStock.eq(inStock));
        }
        return this;
    }

    // Filter by discount status
    public ProductQueryPredicateBuilder byDiscounted(Boolean discounted) {
        if (discounted != null) {
            this.predicate.and(this.product.discounted.eq(discounted));
        }
        return this;
    }

    public Predicate build() {
        return this.predicate;
    }

}
