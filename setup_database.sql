-- ============================================================
-- Database Setup Script for TaskDB
-- Run this script on your SQL Server instance (MSI)
-- ============================================================

USE master;
GO

-- Create database if it doesn't exist
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = N'TaskDB')
BEGIN
    CREATE DATABASE TaskDB;
    PRINT 'Database TaskDB created.';
END
ELSE
BEGIN
    PRINT 'Database TaskDB already exists.';
END
GO

USE TaskDB;
GO

-- ============================================================
-- Users Table
-- ============================================================
IF NOT EXISTS (
    SELECT * FROM sys.tables
    WHERE name = 'Users' AND schema_id = SCHEMA_ID('dbo')
)
BEGIN
    CREATE TABLE [dbo].[Users] (
        [Id]           INT           IDENTITY(1,1) NOT NULL PRIMARY KEY,
        [Username]     NVARCHAR(100) NOT NULL UNIQUE,
        [PasswordHash] NVARCHAR(255) NOT NULL,
        [Role]         NVARCHAR(50)  NOT NULL DEFAULT 'user'
    );
    PRINT 'Table Users created.';

    -- Insert default admin account (change password before production use)
    INSERT INTO [dbo].[Users] (Username, PasswordHash, Role)
    VALUES ('admin', 'admin123', 'admin');

    PRINT 'Default admin user inserted (username: admin, password: admin123).';
END
ELSE
BEGIN
    PRINT 'Table Users already exists.';
END
GO

-- ============================================================
-- Projects Table
-- ============================================================
IF NOT EXISTS (
    SELECT * FROM sys.tables
    WHERE name = 'Projects' AND schema_id = SCHEMA_ID('dbo')
)
BEGIN
    CREATE TABLE [dbo].[Projects] (
        [Id]                 INT            IDENTITY(1,1) NOT NULL PRIMARY KEY,
        [Item]               NVARCHAR(255)  NULL,
        [SourceOfFund]       NVARCHAR(100)  NULL,
        [Sector]             NVARCHAR(100)  NULL,
        [ProjectTitle]       NVARCHAR(500)  NULL,
        [Payment]            DECIMAL(18,2)  NULL,
        [NoOfCalendarDays]   INT            NULL,
        [BiddingDate]        DATE           NULL,
        [NOA]                DATE           NULL,
        [NTP]                DATE           NULL,
        [TargetCompletion]   DATE           NULL,
        [COC]                DATE           NULL,
        [ProjectType]        NVARCHAR(100)  NULL,
        [TypeOfConstruction] NVARCHAR(100)  NULL,
        [Status]             NVARCHAR(100)  NULL,
        [Remarks]            NVARCHAR(MAX)  NULL,
        [LastModifiedDate]   DATETIME       NULL DEFAULT GETDATE()
    );
    PRINT 'Table Projects created.';

    -- Insert sample records
    INSERT INTO [dbo].[Projects]
        (Item, SourceOfFund, Sector, ProjectTitle, Payment, NoOfCalendarDays,
         BiddingDate, NOA, NTP, TargetCompletion, COC,
         ProjectType, TypeOfConstruction, Status, Remarks, LastModifiedDate)
    VALUES
        ('Item 001', 'Government', 'Transportation',
         'Construction of Road along Brgy. Sample',
         1500000.00, 120,
         '2025-01-15', '2025-02-01', '2025-02-10', '2025-06-10', NULL,
         'Road', 'New', 'Ongoing', NULL, GETDATE()),

        ('Item 002', 'Donor', 'Health',
         'Rehabilitation of Health Center Building',
         850000.00, 90,
         '2025-03-05', '2025-03-20', '2025-03-25', '2025-06-22', '2025-06-25',
         'Building', 'Rehab', 'Done', 'Completed ahead of schedule', GETDATE());

    PRINT 'Sample project records inserted.';
END
ELSE
BEGIN
    PRINT 'Table Projects already exists.';
END
GO

PRINT 'Database setup complete.';
GO
