// Command seed creates the tenant, user and clients that the conformance
// tests (tests/conformance), the OpenID Foundation conformance suite
// (scripts/conformance) and the load tests (tests/load) run against.
//
// It is for test databases only: the credentials are fixed and printed. Run
// it after the server has started once, so the schema exists:
//
//	go run ./tests/conformance/seed -database-url "$DATABASE_URL" -domain 127.0.0.1
//
// Seeding is idempotent: rows that already exist are left alone.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"shieldgate/internal/models"
	"shieldgate/tests/conformance/fixture"
)

// seedBcryptCost matches what the server uses for client secrets
// (bcrypt.DefaultCost), so the load tests measure a realistic cost
const seedBcryptCost = 10

type seedClient struct {
	clientID     string
	name         string
	public       bool
	authMethod   string
	grantTypes   []string
	scopes       []string
	redirectURIs []string
}

func main() {
	databaseURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL URL of the server's database")
	domain := flag.String("domain", "127.0.0.1", "host the tenant is reached at (the host of SERVER_URL)")
	flag.Parse()
	if *databaseURL == "" {
		fmt.Fprintln(os.Stderr, "seed: -database-url (or DATABASE_URL) is required")
		os.Exit(2)
	}

	db, err := gorm.Open(postgres.Open(*databaseURL), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		fail(err)
	}
	if err := seed(db, strings.ToLower(*domain)); err != nil {
		fail(err)
	}

	fmt.Printf("tenant_id=%s domain=%s\n", fixture.TenantID, *domain)
	fmt.Printf("user=%s user2=%s password=%s\n", fixture.UserEmail, fixture.User2Email, fixture.UserPassword)
	fmt.Printf("confidential clients=%s,%s,%s secret=%s\n", fixture.ConfidentialClient, fixture.ConfidentialClientPost, fixture.MachineClient, fixture.ClientSecret)
	fmt.Println("public client=" + fixture.PublicClient)
}

func seed(db *gorm.DB, domain string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&models.Tenant{}).Where("id = ?", fixture.TenantID).Count(&count).Error; err != nil {
			return fmt.Errorf("check tenant: %w", err)
		}
		if count > 0 {
			fmt.Println("already seeded")
			return nil
		}

		if err := tx.Create(&models.Tenant{ID: fixture.TenantID, Name: "Conformance", Domain: domain, IsActive: true}).Error; err != nil {
			return fmt.Errorf("create tenant: %w", err)
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(fixture.UserPassword), seedBcryptCost)
		if err != nil {
			return err
		}
		users := []*models.User{
			{ID: fixture.UserID, Username: "conformance", Email: fixture.UserEmail, FirstName: "Connie", LastName: "Formance",
				PhoneNumber: "+15555550100", PhoneVerified: true},
			{ID: fixture.User2ID, Username: "conformance2", Email: fixture.User2Email, FirstName: "Second", LastName: "User"},
		}
		for _, u := range users {
			u.TenantID, u.PasswordHash, u.Status, u.EmailVerified = fixture.TenantID, string(passwordHash), models.UserStatusActive, true
			u.Locale, u.Timezone = "en", "UTC"
			if err := tx.Create(u).Error; err != nil {
				return fmt.Errorf("create user %s: %w", u.Username, err)
			}
		}

		secretHash, err := bcrypt.GenerateFromPassword([]byte(fixture.ClientSecret), seedBcryptCost)
		if err != nil {
			return err
		}
		oidcScopes := []string{"openid", "profile", "email", "phone", "read", "write"}
		codeGrants := []string{"authorization_code", "refresh_token"}
		redirects := append([]string{fixture.RedirectURI}, fixture.OIDFRedirectURIs...)
		clients := []seedClient{
			{fixture.ConfidentialClient, "Conformance RP", false, "client_secret_basic", codeGrants, oidcScopes, redirects},
			{fixture.ConfidentialClientPost, "Conformance RP 2", false, "client_secret_post", codeGrants, oidcScopes, redirects},
			{fixture.PublicClient, "Conformance SPA", true, "none", codeGrants, oidcScopes, redirects},
			{fixture.MachineClient, "Load test M2M", false, "client_secret_basic", []string{"client_credentials"}, []string{"read", "write"}, nil},
		}
		for _, sc := range clients {
			client := &models.Client{
				TenantID: fixture.TenantID, ClientID: sc.clientID, Name: sc.name, IsPublic: sc.public,
				TokenEndpointAuthMethod: sc.authMethod,
				GrantTypes:              models.StringArray(sc.grantTypes),
				Scopes:                  models.StringArray(sc.scopes),
				RedirectURIs:            models.StringArray(nonNil(sc.redirectURIs)),
				PostLogoutRedirectURIs:  models.StringArray{fixture.PostLogoutURI, fixture.OIDFPostLogoutRedirectURI},
			}
			if !sc.public {
				client.ClientSecret = string(secretHash)
			}
			if err := tx.Create(client).Error; err != nil {
				return fmt.Errorf("create client %s: %w", sc.clientID, err)
			}
		}
		return nil
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "seed:", err)
	os.Exit(1)
}
