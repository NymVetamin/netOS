package store

// SetShowHints changes only the account's presentation preference.
func (s *Store) SetShowHints(username string, enabled bool) error {
	_, err := s.db.Exec(`INSERT INTO user_preferences(username, show_hints) VALUES(?, ?)
        ON CONFLICT(username) DO UPDATE SET show_hints=excluded.show_hints`, username, enabled)
	return err
}
