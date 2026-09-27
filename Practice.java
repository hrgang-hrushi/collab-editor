/*
Name: Hrushikesh
Date: September 17, 2026
Course: CSC151
Lab: Training Arena Challenge
Program Description:
Lab 1.
*/
import java.util.Scanner;
class TrainingArena {
public static void main(String[] args) {
Scanner input = new Scanner(System.in);
// Declare variables
String characterName;
String characterClass = "";
String rank = "";
int classChoice;
int damageBonus = 0;
int damage;
int totalDamage = 0;
System.out.println("================================");
System.out.println(" TRAINING ARENA");
System.out.println("================================");
// ------------------------------------
// PART 1: CREATE YOUR CHARACTER
// ------------------------------------
// Ask the player to enter a character name.
System.out.print("Enter your character name: ");
characterName = input.nextLine();
// Display the class menu.
// Use a do-while loop to make sure the player
// enters 1, 2, or 3.
do {
System.out.println();
System.out.println("Choose your class:");
System.out.println("1. Warrior");
System.out.println("2. Rogue");
System.out.println("3. Mage");
System.out.print("Enter your choice (1, 2, or 3): ");
classChoice = input.nextInt();
if (classChoice < 1 || classChoice > 3) {
System.out.println("Invalid choice. Please try again.");
}
} while (classChoice < 1 || classChoice > 3);
// Use a switch statement to assign the
// character class and damage bonus.
switch (classChoice) {
case 1:
characterClass = "Warrior";
damageBonus = 3;
break;
case 2:
characterClass = "Rogue";
damageBonus = 2;
break;
case 3:
characterClass = "Mage";
damageBonus = 4;
break;
}
// Display the character's name and class
// and announce that they are entering the
// Training Arena.
System.out.println();
System.out.println(characterName + " the " + characterClass
+ " enters the Training Arena!");
// Clear the newline left in the input buffer
// after using nextInt().
input.nextLine();
// ------------------------------------
// PART 2: TRAINING ROUNDS
// ------------------------------------
// Create an outer for loop that runs 3 rounds.

for (int round = 1; round <= 3; round++) {
// Display the current round number.
System.out.println();
System.out.println("=== ROUND " + round + " ===");
// Wait for the player to press Enter before
// beginning the round.
System.out.print("Press Enter to begin the round...");
input.nextLine();
System.out.println();
// Create an inner for loop that performs
// 5 attacks during each round.
for (int attack = 1; attack <= 5; attack++) {
// Generate a random base damage
// value from 1 through 10.
damage = (int)(Math.random() * 10) + 1;
// Add the character's damage bonus
// to the damage.
damage = damage + damageBonus;
// Add the damage to totalDamage.
totalDamage = totalDamage + damage;
// Display the attack number and damage.
System.out.println("Attack " + attack + ": "
+ damage + " damage");
}
// Display the total damage so far
// after each round.
System.out.println();
System.out.println("Total damage so far: " + totalDamage);
}
// ------------------------------------
// PART 3: DETERMINE FINAL RANK
// ------------------------------------
// Use if / else if / else to determine
// the character's rank based on totalDamage.
if (totalDamage >= 150) {
rank = "Arena Champion";
} else if (totalDamage >= 100) {
rank = "Elite Fighter";
} else {
rank = "Apprentice";
}
// ------------------------------------
// PART 4: DISPLAY FINAL RESULTS
// ------------------------------------
// Display:
// Character name
// Character class
// Total attacks
// Total damage
// Final rank
System.out.println();
System.out.println("================================");
System.out.println(" TRAINING COMPLETE");
System.out.println("================================");
System.out.println();
System.out.println("Character: " + characterName);
System.out.println("Class: " + characterClass);
System.out.println("Total Attacks: 15");
System.out.println("Total Damage: " + totalDamage);
System.out.println("Rank: " + rank);
input.close();
}
}
