CREATE NAMESPACE users;

{users}CREATE TABLE users (
  id INT8 PRIMARY KEY,
  name TEXT UNIQUE,
  owner_address TEXT NOT NULL UNIQUE
);

{users}CREATE ACTION create_user($id int, $name TEXT) public {
  INSERT INTO users (id, name, owner_address) VALUES ($id, $name, @caller);
};

{users}CREATE ACTION get_users() public view returns (name text, address text) {
  return SELECT name, owner_address FROM users;
};
