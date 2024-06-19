using frontendnet.Models;

namespace frontendnet.Services;

public class CategoriasClientService(HttpClient client)
{
    public async Task<List<Categoria>?> GetAsync()
    {
        return await client.GetFromJsonAsync<List<Categoria>>("api/categorias");
    }

    public async Task<Categoria?> GetAsync(int id)
    {
        return await client.GetFromJsonAsync<Categoria>($"api/categorias/{id}");
    }

    public async Task<bool> PostAsync(Categoria categoria)
    {
        var response = await client.PostAsJsonAsync($"api/categorias", categoria);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> PutAsync(Categoria categoria)
    {
        var response = await client.PutAsJsonAsync($"api/categorias/{categoria.CategoriaId}", categoria);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> DeleteAsync(int id)
    {
        var response = await client.DeleteAsync($"api/categorias/{id}");
        return response.IsSuccessStatusCode;
    }
}