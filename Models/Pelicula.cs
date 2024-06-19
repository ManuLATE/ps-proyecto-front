using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace frontendnet.Models;

public class Pelicula
{
    [Display(Name = "Id")]
    public int? PeliculaId { get; set; }

    [Required(ErrorMessage = "El campo {0} es obligatorio.")]
    public required string Titulo { get; set; }

    [Required(ErrorMessage = "El campo {0} es obligatorio.")]
    [DataType(DataType.MultilineText)]
    public string Sinopsis { get; set; } = "Sin sinopsis";

    [Required(ErrorMessage = "El campo {0} es obligatorio.")]
    [Range(1950, 2024, ErrorMessage = "El valor del campo {0} debe estar entre {1} y {2}.")]
    [Display(Name = "Año")]
    public int Anio { get; set; }

    [Display(Name = "Portada")]
    public int? ArchivoId { get; set; }

    [Display(Name = "Eliminable")]
    public bool Protegida { get; set; } = false;

    public ICollection<Categoria>? Categorias { get; set; }
}