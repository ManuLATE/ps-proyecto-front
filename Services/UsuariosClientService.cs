using frontendnet.Models;

namespace frontendnet.Services;

public class UsuariosClientService(HttpClient client)
{
    public async Task<List<Usuario>?> GetAsync()
    {
        return await client.GetFromJsonAsync<List<Usuario>>("api/usuarios");
    }

    public async Task<Usuario?> GetAsync(string email)
    {
        return await client.GetFromJsonAsync<Usuario>($"api/usuarios/{email}");
    }

    public async Task<bool> PostAsync(UsuarioPwd usuario)
    {
        var response = await client.PostAsJsonAsync($"api/usuarios", usuario);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> PutAsync(Usuario usuario)
    {
        var response = await client.PutAsJsonAsync($"api/usuarios/{usuario.Email}", usuario);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> DeleteAsync(string email)
    {
        var response = await client.DeleteAsync($"api/usuarios/{email}");
        return response.IsSuccessStatusCode;
    }
}