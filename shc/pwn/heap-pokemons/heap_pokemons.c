
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>


struct pokemon {
   char pokemon_id;
   char  *name;
};


struct pokemon *POKEMONS[10];


char pokemon_names[151][16] = {
  "Abra", "Aerodactyl", "Alakazam", "Arbok", "Arcanine", "Articuno", "Beedrill", "Bellsprout", "Blastoise", "Bulbasaur", "Butterfree", "Caterpie", "Chansey", "Charizard", "Charmander", "Charmeleon", "Clefable", "Clefairy", "Cloyster", "Cubone", "Dewgong", "Diglett", "Ditto", "Dodrio", "Doduo", "Dragonair", "Dragonite", "Dratini", "Drowzee", "Dugtrio", "Eevee", "Ekans", "Electabuzz", "Electrode", "Exeggcute", "Exeggutor", "Farfetch'd", "Fearow", "Flareon", "Gastly", "Gengar", "Geodude", "Gloom", "Golbat", "Goldeen", "Golduck", "Golem", "Graveler", "Grimer", "Growlithe", "Gyarados", "Haunter", "Hitmonchan", "Hitmonlee", "Horsea", "Hypno", "Ivysaur", "Jigglypuff", "Jolteon", "Jynx", "Kabuto", "Kabutops", "Kadabra", "Kakuna", "Kangaskhan", "Kingler", "Koffing", "Krabby", "Lapras", "Lickitung", "Machamp", "Machoke", "Machop", "Magikarp", "Magmar", "Magnemite", "Magneton", "Mankey", "Marowak", "Meowth", "Metapod", "Mew", "Mewtwo", "Moltres", "Mr. Mime", "Muk", "Nidoking", "Nidoqueen", "Nidoran♀", "Nidoran♂", "Nidorina", "Nidorino", "Ninetales", "Oddish", "Omanyte", "Omastar", "Onix", "Paras", "Parasect", "Persian", "Pidgeot", "Pidgeotto", "Pidgey", "Pikachu", "Pinsir", "Poliwag", "Poliwhirl", "Poliwrath", "Ponyta", "Porygon", "Primeape", "Psyduck", "Raichu", "Rapidash", "Raticate", "Rattata", "Rhydon", "Rhyhorn", "Sandshrew", "Sandslash", "Scyther", "Seadra", "Seaking", "Seel", "Shellder", "Slowbro", "Slowpoke", "Snorlax", "Spearow", "Squirtle", "Starmie", "Staryu", "Tangela", "Tauros", "Tentacool", "Tentacruel", "Vaporeon", "Venomoth", "Venonat", "Venusaur", "Victreebel", "Vileplume", "Voltorb", "Vulpix", "Wartortle", "Weedle", "Weepinbell", "Weezing", "Wigglytuff", "Zapdos", "Zubat"
};


int get_random_pokemon_id() {
  char random_pokemon_id_char;
  FILE *urandom_fd;

  urandom_fd = fopen("/dev/urandom", "r");
  fread(&random_pokemon_id_char, 4, 1, urandom_fd);
  fclose(urandom_fd);

  int random_pokemon_id = random_pokemon_id_char % 151;
  if(random_pokemon_id < 0) { random_pokemon_id *= -1; }

  return random_pokemon_id;
}

int get_pokemon_name_size() {
  // get size for the pokemon name
  printf("Pokemon Name Size: ");
  fflush(stdout);
  int pokemon_name_size;
  scanf("%d", &pokemon_name_size);

  if(pokemon_name_size < 0) {
    pokemon_name_size = 0;
  }

  return pokemon_name_size;
}






int get_pokemon_index() {
  // get index of a pokemon
  printf("Pokemon Index: ");
  fflush(stdout);
  int pokemon_index;
  scanf("%d", &pokemon_index);

  if(pokemon_index < 0 || pokemon_index > 10) {
    pokemon_index = 0;
  }

  return pokemon_index;
}


void show_pokemon() {
  int pokemon_index = get_pokemon_index();
  struct pokemon *selected_pokemon = POKEMONS[pokemon_index];

  if(selected_pokemon != 0) {
    printf("Pokemon Name: %s", selected_pokemon->name);
    fflush(stdout);

    char *pokemonsay_name = pokemon_names[selected_pokemon->pokemon_id];

    char pokemonsay_cmd[100];
    sprintf(pokemonsay_cmd, "pokemonsay -p %s ohai", pokemonsay_name);
    system(pokemonsay_cmd);
    fflush(stdout);
  }
  else {
    puts("Nope");
    fflush(stdout);
  }

}



void add_pokemon() {
  // get index of new pokemon
  int new_pokemon_index = 0;

  for(int i = 0; i < 10; i++) {
    struct pokemon *selected_pokemon = POKEMONS[i];
    if(selected_pokemon == 0) {
      new_pokemon_index = i;
      break;
    }
  }

  struct pokemon *selected_pokemon = malloc(sizeof(struct pokemon));
  POKEMONS[new_pokemon_index] = selected_pokemon;

  printf("New Pokemon Index = %d\n", new_pokemon_index);
  fflush(stdout);

  // set pokemon values
  selected_pokemon->pokemon_id = get_random_pokemon_id();

  int pokemon_name_size = get_pokemon_name_size();

  selected_pokemon->name = malloc(pokemon_name_size);
  printf("New Pokemon Name: ");
  fflush(stdout);
  char newline = getchar();
  fgets(selected_pokemon->name, pokemon_name_size, stdin);
}


void edit_pokemon() {

  int pokemon_index = get_pokemon_index();
  // check if pokemon exists
  if(POKEMONS[pokemon_index] != 0) {
    struct pokemon *selected_pokemon = POKEMONS[pokemon_index];

    printf("New Pokemon Name: ");
    fflush(stdout);
    char newline = getchar();
    fgets(selected_pokemon->name, 2048, stdin);
  }
  else {
    puts("Nope");
    fflush(stdout);
  }
}


void delete_pokemon() {
  // get id to delete
  int pokemon_index = get_pokemon_index();
  // check if pokemon exists
  if(POKEMONS[pokemon_index] != 0) {

    struct pokemon *selected_pokemon = POKEMONS[pokemon_index];

    // delete pokemon
    selected_pokemon->pokemon_id = 0;
    memset(selected_pokemon->name, 0, sizeof(selected_pokemon->name));
    free(selected_pokemon->name);
    POKEMONS[pokemon_index] = 0;
  }
  else {
    puts("Nope");
    fflush(stdout);
  }
}



void menu() {
  puts("-----");
  puts("Welcome to Heap Pokemons!");
  puts("- Here you can put pokemons on the heap!!!");
  puts("- /mnt/ain is the coolest gang in the city and you know it!");
  puts("- by ❤️ ❤️ ❤️  muffinx (https://twitter.com/_muffinx) ❤️ ❤️ ❤️");
  puts("-----");
  puts("1 - Add Pokemon");
  puts("2 - Edit Pokemon");
  puts("3 - Show Pokemon");
  puts("4 - Delete Pokemon");


  printf("Input: ");
  fflush(stdout);
  int user_input_num;
  scanf("%d", &user_input_num);
  puts("-----");
  fflush(stdout);


  if(user_input_num == 1) {
    add_pokemon();
  }
  else if(user_input_num == 2) {
    edit_pokemon();
  }
  else if(user_input_num == 3) {
    show_pokemon();
  }
  else if(user_input_num == 4) {
    delete_pokemon();
  }
  else {
    puts("Nope");
    fflush(stdout);
    exit(0);
  }


}



void main() {
  while(1) {
    menu();
  }
}
