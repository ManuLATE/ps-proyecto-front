using frontendnet.Models;

namespace frontendnet.Services;

public class PeliculasClientService(HttpClient client)
{
    public async Task<List<Pelicula>?> GetAsync(string? search)
    {
        return await client.GetFromJsonAsync<List<Pelicula>>($"api/peliculas?s={search}");
    }

    public async Task<Pelicula?> GetAsync(int id)
    {
        return await client.GetFromJsonAsync<Pelicula>($"api/peliculas/{id}");
    }

    public async Task<bool> PostAsync(Pelicula pelicula)
    {
        var response = await client.PostAsJsonAsync($"api/peliculas", pelicula);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> PutAsync(Pelicula pelicula)
    {
        var response = await client.PutAsJsonAsync($"api/peliculas/{pelicula.PeliculaId}", pelicula);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> DeleteAsync(int id)
    {
        var response = await client.DeleteAsync($"api/peliculas/{id}");
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> PostAsync(int id, int categoriaid)
    {
        var response = await client.PostAsJsonAsync($"api/peliculas/{id}/categoria", new { categoriaid });
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> DeleteAsync(int id, int categoriaid)
    {
        var response = await client.DeleteAsync($"api/peliculas/{id}/categoria/{categoriaid}");
        return response.IsSuccessStatusCode;
    }
}