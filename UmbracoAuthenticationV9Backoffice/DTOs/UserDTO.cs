namespace UmbracoAuthenticationV9Backoffice.DTOs
{
    public class UserDTO
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        public UserDTO(string username, string password)
        {
            Username = username;
            Password = password;
        }

        public UserDTO()
        {

        }
    }
}
