const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/authMiddleware');
const authorizeAdmin = require('../middleware/roleMiddleware');
const User = require('../models/User');
const Application = require('../models/Application');
const validator = require('validator');
const sequelize = require('../config/db');

/**
 * @openapi
 * /api/users:
 *   get:
 *     summary: Get all users
 *     tags:
 *       - [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successful response with all users
 *       500:
 *         description: Server error while fetching users
 */
router.get('/users', authorizeAdmin, async (req, res) => {
  try {
    const allUsers = await User.findAll();
    res.json(allUsers);
  } catch (err) {
    res.status(500).json({ error: "Could not fetch users" });
  }
});

/**
 * @openapi
 * /api/users/{id}:
 *   delete:
 *     summary: delete a user by ID
 *     tags:
 *       - [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user to delete
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       500:
 *         description: Could not delete user
 */
router.delete('/users/:id',authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await Application.destroy({ where: { userId: id } });
    // On cherche l'utilisateur
    const userToDelete = await User.findByPk(id);
    if (!userToDelete) {
      return res.status(404).json({ error: "User not found" });
    }
    await userToDelete.destroy();
    console.log(`✅ User with ID ${id} deleted.`);
    res.status(200).json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Delete Error:", err);
    res.status(500).json({ error: "Server error during deletion" });
  }
});

router.get('/users/search-by-bio/:searchTerm', async (req, res) => {
  try {
    const { searchTerm } = req.params;
    const users = await User.findAll({ where: { bio: { [require('sequelize').Op.like]: `%${searchTerm}%` } } });
    if (users.length === 0) {
      return res.json([]);
    }
    return res.json(users);
  } catch (err) {
    return res.status(500).json({ error: 'Erreur lors de la recherche', details: err.message });
  }
});

/**
 * @openapi
 * /api/users/create:
 *   post:
 *     summary: Create a new user
 *     tags:
 *       - [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *     responses:
 *       201:
 *         description: User created successfully
 *       500:
 *         description: Could not create user
 */ 
router.post('/users/create',authorizeAdmin, async (req, res) => {
  try { 
    const { name, email, password, role } = req.body; 
    const newUser = await User.create({ name, email, password, role }); 
    await newUser.save();
    res.status(201).json(newUser); 
  } catch (err) { 
    res.status(500).json({ error: "Could not create user" }); 
  }
});

/**
 * @openapi
 * /api/users/{id}/edit:
 *   post:
 *     summary: edit a user by ID
 *     tags:
 *       - [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user to edit
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: User edited successfully
 *       500:
 *         description: Could not edit user
 */ 
router.post('/users/:id/edit',authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, bio} = req.body;
    console.log(bio);
    const cleanName = validator.escape(name);
    const userToEdit = await User.findByPk(id);
    if (!userToEdit) {
      return res.status(404).json({ error: "User not found" });
    }
    userToEdit.name = cleanName
    userToEdit.email = email 
    userToEdit.bio = bio; // Vulnérabilité XSS potentielle si bio n'est pas nettoyé côté client
    await userToEdit.save();
    res.status(200).json(userToEdit); 
  } 
  catch (err) {
    res.status(500).json({ error: "Could not update user" });
  }
});

/**
 * @openapi
 * /api/users/{id}/switchRole:
 *   post:
 *     summary: switch a user's role
 *     tags:
 *       - [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user whose role is to be switched
 *     responses:
 *       200:
 *         description: User role switched successfully
 *       500:
 *         description: Could not switch user role
 */ 
router.post('/users/:id/switchRole', authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const userToEdit = await User.findByPk(id);
    if (!userToEdit) {
      return res.status(404).json({ error: "User not found" });
    }
    const oldRole = userToEdit.role;
    userToEdit.role = oldRole === 'ADMIN' ? 'USER' : 'ADMIN';
    await userToEdit.save();

    console.log(`[AUTH] Role switched for ${userToEdit.name}: ${oldRole} -> ${userToEdit.role}`);
    res.status(200).json(userToEdit);
  } catch (err) {
    res.status(500).json({ error: "Could not switch user role" });
  }
});
module.exports = router;